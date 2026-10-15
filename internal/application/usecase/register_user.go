package usecase

import (
	"context"
	"errors"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RegisterUserPorts are the outbound ports RegisterUser needs.
type RegisterUserPorts struct {
	Users        out.UserRepository
	Keys         out.IdempotencyKeyRepository
	Outbox       out.OutboxWriter
	Hasher       out.PasswordHasher
	IDs          out.IDGenerator
	Clock        out.Clock
	Transactions out.TransactionManager
	Tokens       out.TokenIssuer
	Sessions     in.IssueRefreshToken
}

// RegisterUser implements in.RegisterUser (HU-AUTH-001, Norma 5.3.8).
type RegisterUser struct {
	ports   RegisterUserPorts
	session sessionIssuer
}

var _ in.RegisterUser = (*RegisterUser)(nil)

// NewRegisterUser wires the use case with the ports it needs.
func NewRegisterUser(ports RegisterUserPorts) *RegisterUser {
	return &RegisterUser{ports: ports, session: sessionIssuer{tokens: ports.Tokens, sessions: ports.Sessions, clock: ports.Clock}}
}

type registration struct {
	key         model.IdempotencyKey
	requestHash string
	candidate   *model.User
	event       model.UserRegistered
}

// Register validates the command and, in one transaction, looks the idempotency key up first.
// A key already used by the same request is a replay (the account, no tokens, nothing created);
// by another request, model.ErrIdempotencyKeyConflict; a new key saves the CLIENT user, the key
// and the UserRegistered event together, and the tokens are issued after the commit.
//
// A concurrent request with the same key loses on the key or on the unique email index: it rolls
// back and looks the key up once more in a new transaction, which now sees the winner. The
// retry is bounded to one.
func (r *RegisterUser) Register(ctx context.Context, command in.RegisterUserCommand) (in.RegisterUserResult, error) {
	request, err := r.newRegistration(command)
	if err != nil {
		return in.RegisterUserResult{}, err
	}
	existing, err := r.registerOnce(ctx, request)
	if lostRace(err) {
		existing, err = r.registerOnce(ctx, request)
	}
	if err != nil {
		return in.RegisterUserResult{}, err
	}
	if existing != nil {
		summary, err := summarizeUser(existing)
		if err != nil {
			return in.RegisterUserResult{}, err
		}
		return in.RegisterUserResult{Replayed: true, Session: in.LoginUserResult{User: summary}}, nil
	}
	session, err := r.session.open(ctx, request.candidate, command.UserAgent)
	if err != nil {
		return in.RegisterUserResult{}, err
	}
	return in.RegisterUserResult{Session: session}, nil
}

func lostRace(err error) bool {
	return errors.Is(err, model.ErrIdempotencyKeyTaken) || errors.Is(err, model.ErrEmailAlreadyRegistered)
}

// registerOnce runs one transaction: it returns the account of a replay, or nil after creating one.
func (r *RegisterUser) registerOnce(ctx context.Context, request registration) (*model.User, error) {
	var existing *model.User
	err := r.ports.Transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		existing = nil
		record, found, err := r.ports.Keys.Find(ctx, request.key)
		if err != nil {
			return err
		}
		if found {
			existing, err = r.replay(ctx, record, request.requestHash)
			return err
		}
		return r.create(ctx, request)
	})
	return existing, err
}

func (r *RegisterUser) replay(ctx context.Context, record out.IdempotencyRecord, requestHash string) (*model.User, error) {
	if record.RequestHash != requestHash {
		return nil, model.ErrIdempotencyKeyConflict
	}
	return r.ports.Users.FindByID(ctx, record.UserID)
}

func (r *RegisterUser) create(ctx context.Context, request registration) error {
	taken, err := r.ports.Users.ExistsByEmail(ctx, request.candidate.Email())
	if err != nil {
		return err
	}
	if taken {
		return model.ErrEmailAlreadyRegistered
	}
	if err := r.ports.Users.Save(ctx, request.candidate); err != nil {
		return err
	}
	record := out.IdempotencyRecord{UserID: request.candidate.ID(), RequestHash: request.requestHash}
	if err := r.ports.Keys.Save(ctx, request.key, record); err != nil {
		return err
	}
	return r.ports.Outbox.Append(ctx, request.event)
}

func (r *RegisterUser) newRegistration(command in.RegisterUserCommand) (registration, error) {
	key, err := model.NewIdempotencyKey(command.IdempotencyKey)
	if err != nil {
		return registration{}, err
	}
	candidate, err := r.newUser(command)
	if err != nil {
		return registration{}, err
	}
	return registration{
		key:         key,
		requestHash: model.RegistrationRequestHash(candidate.Email(), candidate.Name(), candidate.Phone(), candidate.Address()),
		candidate:   candidate,
		event:       model.NewUserRegistered(r.ports.IDs.NewID(), r.ports.Clock.Now(), candidate),
	}, nil
}

func (r *RegisterUser) newUser(command in.RegisterUserCommand) (*model.User, error) {
	email, err := model.NewEmail(command.Email)
	if err != nil {
		return nil, err
	}
	password, err := model.NewPassword(command.Password)
	if err != nil {
		return nil, err
	}
	name, err := model.NewName(command.Name)
	if err != nil {
		return nil, err
	}
	phone, err := model.NewPhone(command.Phone)
	if err != nil {
		return nil, err
	}
	address, err := model.NewAddress(command.Address)
	if err != nil {
		return nil, err
	}
	hash, err := r.ports.Hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	return model.NewUser(r.ports.IDs.NewID(), name, email, hash, phone, address, []model.Role{model.RoleClient})
}
