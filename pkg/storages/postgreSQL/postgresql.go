package postgreSQL

import (
	"GophKeeper/pkg/secure"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/storages/storage_errors"
)

// PostgresDB implements the Storage interface using postgreSQL.
type PostgresDB struct {
	db *sql.DB
}

// NewPostgresDB initializes a new PostgresDB instance and creates tables if they do not exist.
func NewPostgresDB(sqlDb *sql.DB) *PostgresDB {
	postgresDB := &PostgresDB{
		db: sqlDb,
	}
	return postgresDB
}

func (p *PostgresDB) OpenConnection(connString string) error {
	var err error
	p.db, err = sql.Open("pgx", connString)
	if err != nil {
		return fmt.Errorf("cant to connect to database: %w", err)
	}
	return nil
}

// initTables creates the necessary tables if they do not already exist.
func (p *PostgresDB) initTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			login TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			password_salt TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS bank_cards (
			id SERIAL PRIMARY KEY,
			owner_id INTEGER NOT NULL REFERENCES users(id),
			last_four_digits INTEGER NOT NULL,
			card_data TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS logins_and_passwords (
			id SERIAL PRIMARY KEY,
			owner_id INTEGER NOT NULL REFERENCES users(id),
			login TEXT NOT NULL,
			password TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS texts (
			id SERIAL PRIMARY KEY,
			owner_id INTEGER NOT NULL REFERENCES users(id),
			text_name TEXT NOT NULL,
			text_data TEXT NOT NULL
		)`,
	}

	for _, query := range queries {
		if _, err := p.db.Exec(query); err != nil {
			return fmt.Errorf("create table err: %w", err)
		}
	}

	return nil
}

// SaveBankCard saves a bank card for a user and returns the inserted record's ID.
func (p *PostgresDB) SaveBankCard(ctx context.Context, ownerID int, lastFourDigits int, cardData string) (int, error) {
	var id int
	query := `INSERT INTO bank_cards (owner_id, last_four_digits, card_data) VALUES ($1, $2, $3) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, ownerID, lastFourDigits, cardData).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("cant insert bank card, err: %w", err)
	}
	return id, nil
}

// GetBankCard retrieves a bank card's data and ID based on the owner ID and last four digits.
func (p *PostgresDB) GetBankCard(ctx context.Context, ownerID int, lastFourDigits int) (string, int, error) {
	var data string
	var dataID int
	query := `SELECT id, card_data FROM bank_cards WHERE owner_id=$1 AND last_four_digits=$2`
	err := p.db.QueryRowContext(ctx, query, ownerID, lastFourDigits).Scan(&dataID, &data)
	if err != nil {
		return "", 0, fmt.Errorf("cant select bank cards err: %w", err)
	}
	return data, dataID, nil
}

// SaveLoginAndPassword saves login and password credentials for a user and returns the inserted record's ID.
func (p *PostgresDB) SaveLoginAndPassword(ctx context.Context, ownerID int, login, password string) (int, error) {
	var id int
	query := `INSERT INTO logins_and_passwords (owner_id, login, password) VALUES ($1, $2, $3) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, ownerID, login, password).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("cant insert login and password, err: %w", err)
	}
	return id, nil
}

// GetPasswordByLogin retrieves the password and ID associated with a specific login for a user.
func (p *PostgresDB) GetPasswordByLogin(ctx context.Context, ownerID int, login string) (string, int, error) {
	var password string
	var dataID int
	query := `SELECT id, password FROM logins_and_passwords WHERE owner_id=$1 AND login=$2`
	err := p.db.QueryRowContext(ctx, query, ownerID, login).Scan(&dataID, &password)
	if err != nil {
		return "", 0, fmt.Errorf("cant get password by login, err: %w", err)
	}
	return password, dataID, nil
}

// SaveText saves a text entry for a user and returns the inserted record's ID.
func (p *PostgresDB) SaveText(ctx context.Context, ownerID int, textName, text string) (int, error) {
	var id int
	query := `INSERT INTO texts (owner_id, text_name, text_data) VALUES ($1, $2, $3) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, ownerID, textName, text).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("cant insert text, err: %w", err)
	}
	return id, nil
}

// GetText retrieves the text data and ID based on the owner ID and text name.
func (p *PostgresDB) GetText(ctx context.Context, ownerID int, textName string) (string, int, error) {
	var textData string
	var dataID int
	query := `SELECT id, text_data FROM texts WHERE owner_id=$1 AND text_name=$2`
	err := p.db.QueryRowContext(ctx, query, ownerID, textName).Scan(&dataID, &textData)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, storage_errors.NewErrNotExists()
	}
	if err != nil {
		return "", 0, fmt.Errorf("cant get text by text, err: %w", err)
	}
	return textData, dataID, nil
}

// CreateUser creates a new user and returns the user's ID.
// It hashes password and saves its hashed version with salt.
func (p *PostgresDB) CreateUser(ctx context.Context, user entities.User) (int, error) {
	passwordHash, salt, err := secure.HashPassword([]byte(user.Password))
	if err != nil {
		return 0, fmt.Errorf("error hashing password: %w", err)
	}

	var id int
	query := `INSERT INTO users (login, password, password_salt) VALUES ($1, $2, $3) RETURNING id`
	err = p.db.QueryRowContext(ctx, query, user.Login, passwordHash, salt).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("error creating user: %w", err)
	}
	return id, nil
}

// AuthUser authenticates a user and returns the user's ID if successful.
func (p *PostgresDB) AuthUser(ctx context.Context, user entities.User) (int, error) {
	query := `SELECT password_salt FROM users WHERE login=$1`
	var salt string
	err := p.db.QueryRowContext(ctx, query, user.Login).Scan(&salt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, storage_errors.NewErrNotExists()
	}

	passwordHash, err := secure.HashPasswordWithSalt([]byte(user.Password), salt)
	if err != nil {
		return 0, fmt.Errorf("cant hash password, err: %w", err)
	}

	var id int
	query = `SELECT id FROM users WHERE login=$1 AND password=$2`
	err = p.db.QueryRowContext(ctx, query, user.Login, passwordHash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, storage_errors.NewErrNotExists()
	} else if err != nil {
		return 0, fmt.Errorf("cant get user by login, err: %w", err)
	}
	return id, nil
}
