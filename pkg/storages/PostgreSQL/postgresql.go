package PostgreSQL

import (
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/storages/storageerrors"
	"context"
	"database/sql"
	"errors"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresDB struct {
	db *sql.DB
}

// NewPostgresDB
func NewPostgresDB(connString string) (*PostgresDB, error) {

	db, err := sql.Open("pgx", connString)
	if err != nil {
		return nil, err
	}

	postgresDB := &PostgresDB{db: db}

	if err := postgresDB.initTables(); err != nil {
		return nil, err
	}

	return postgresDB, nil
}

// initTables creates tables if they are not exists.
func (p *PostgresDB) initTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            login TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS bank_cards (
            id SERIAL PRIMARY KEY,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            last_four_digits INTEGER NOT NULL,
            card_data BYTEA NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS logins_and_passwords (
            id SERIAL PRIMARY KEY,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            login TEXT NOT NULL,
            password TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS binary_data (
            id SERIAL PRIMARY KEY,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            data_name TEXT NOT NULL,
            data BYTEA NOT NULL
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
			return err
		}
	}

	return nil
}

// Storage interface implementation

func (p *PostgresDB) SaveBankCard(ctx context.Context, ownerID int, lastFourDigits int, cardData []byte) (int, error) {
	var id int
	query := `INSERT INTO bank_cards (owner_id, last_four_digits, card_data) VALUES ($1, $2, $3) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, ownerID, lastFourDigits, cardData).Scan(&id)
	return id, err
}

func (p *PostgresDB) GetBankCard(ctx context.Context, ownerID int, lastFourDigits int) ([]byte, int, error) {
	var data []byte
	var dataID int
	query := `SELECT id, card_data FROM bank_cards WHERE owner_id=$1 AND last_four_digits=$2`
	err := p.db.QueryRowContext(ctx, query, ownerID, lastFourDigits).Scan(&dataID, &data)
	return data, dataID, err
}

func (p *PostgresDB) SaveLoginAndPassword(ctx context.Context, ownerID int, login, password string) (int, error) {
	var id int
	query := `INSERT INTO logins_and_passwords (owner_id, login, password) VALUES ($1, $2, $3) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, ownerID, login, password).Scan(&id)
	return id, err
}

func (p *PostgresDB) GetPasswordByLogin(ctx context.Context, ownerID int, login string) (string, int, error) {
	var password string
	var dataID int
	query := `SELECT id, password FROM logins_and_passwords WHERE owner_id=$1 AND login=$2`
	err := p.db.QueryRowContext(ctx, query, ownerID, login).Scan(&dataID, &password)
	return password, dataID, err
}

func (p *PostgresDB) SaveBinaryData(ctx context.Context, ownerID int, dataName string, data []byte) (int, error) {
	var id int
	query := `INSERT INTO binary_data (owner_id, data_name, data) VALUES ($1, $2, $3) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, ownerID, dataName, data).Scan(&id)
	return id, err
}

func (p *PostgresDB) GetBinaryData(ctx context.Context, ownerID int, dataName string) ([]byte, int, error) {
	var data []byte
	var dataID int
	query := `SELECT id, data FROM binary_data WHERE owner_id=$1 AND data_name=$2`
	err := p.db.QueryRowContext(ctx, query, ownerID, dataName).Scan(&dataID, &data)
	return data, dataID, err
}

func (p *PostgresDB) SaveText(ctx context.Context, ownerID int, textName, text string) (int, error) {
	var id int
	query := `INSERT INTO texts (owner_id, text_name, text_data) VALUES ($1, $2, $3) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, ownerID, textName, text).Scan(&id)
	return id, err
}

func (p *PostgresDB) GetText(ctx context.Context, ownerID int, textName string) ([]byte, int, error) {
	var textData string
	var dataID int
	query := `SELECT id, text_data FROM texts WHERE owner_id=$1 AND text_name=$2`
	err := p.db.QueryRowContext(ctx, query, ownerID, textName).Scan(&dataID, &textData)
	return []byte(textData), dataID, err
}

// UserManager interface implementation

func (p *PostgresDB) CreateUser(ctx context.Context, user entities.User) (int, error) {
	var id int
	query := `INSERT INTO users (login, password) VALUES ($1, $2) RETURNING id`
	err := p.db.QueryRowContext(ctx, query, user.Login, user.Password).Scan(&id)
	return id, err
}

func (p *PostgresDB) AuthUser(ctx context.Context, user entities.User) (int, error) {
	var id int
	query := `SELECT id FROM users WHERE login=$1 AND password=$2`
	err := p.db.QueryRowContext(ctx, query, user.Login, user.Password).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, storageerrors.NewErrNotExists()
	}
	return id, err
}
