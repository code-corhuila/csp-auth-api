package usecase

import (
	"context"

	"github.com/code-corhuila/csp-auth-api/internal/application/port/in"
	"github.com/code-corhuila/csp-auth-api/internal/application/port/out"
	"github.com/code-corhuila/csp-auth-api/internal/domain/model"
)

// RegisterUser implements in.RegisterUser (HU-AUTH-001).
type RegisterUser struct {
	users        out.UserRepository
	outbox       out.OutboxWriter
	hasher       out.PasswordHasher
	ids          out.IDGenerator
	clock        out.Clock
	transactions out.TransactionManager
}

var _ in.RegisterUser = (*RegisterUser)(nil)

// NewRegisterUser wires the use case with the ports it needs.
func NewRegisterUser(users out.UserRepository, outbox out.OutboxWriter, hasher out.PasswordHasher, ids out.IDGenerator, clock out.Clock, transactions out.TransactionManager) *RegisterUser {
	return &RegisterUser{users: users, outbox: outbox, hasher: hasher, ids: ids, clock: clock, transactions: transactions}
}

// Register validates the command, rejects an email already in use and, in one transaction,
// saves the new CLIENT user and records UserRegistered in the outbox.
func (r *RegisterUser) Register(ctx context.Context, command in.RegisterUserCommand) (in.RegisterUserResult, error) {
	candidate, err := r.newUser(command)
	if err != nil {
		return in.RegisterUserResult{}, err
	}
	event := model.NewUserRegistered(r.ids.NewID(), r.clock.Now(), candidate)

	err = r.transactions.WithinTransaction(ctx, func(ctx context.Context) error {
		taken, err := r.users.ExistsByEmail(ctx, candidate.Email())
		if err != nil {
			return err
		}
		if taken {
			return model.ErrEmailAlreadyRegistered
		}
		if err := r.users.Save(ctx, candidate); err != nil {
			return err
		}
		return r.outbox.Append(ctx, event)
	})
	if err != nil {
		return in.RegisterUserResult{}, err
	}
	return in.RegisterUserResult{UserID: event.UserID, Email: event.Email, Name: candidate.Name().String(), Roles: event.Roles}, nil
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
	hash, err := r.hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	return model.NewUser(r.ids.NewID(), name, email, hash, phone, address, []model.Role{model.RoleClient})
}
