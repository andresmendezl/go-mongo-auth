package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type userDoc struct {
	ID           bson.ObjectID `bson:"_id"`
	Username     string        `bson:"username"`
	PasswordHash []byte        `bson:"passwordHash"`
	CreatedAt    time.Time     `bson:"createdAt"`
}

func (d userDoc) toUser() User {
	return User{ID: d.ID.Hex(), Username: d.Username, PasswordHash: d.PasswordHash, CreatedAt: d.CreatedAt}
}

type sessionDoc struct {
	ID        string        `bson:"_id"` // sha256 of the token
	UserID    bson.ObjectID `bson:"userId"`
	ExpiresAt time.Time     `bson:"expiresAt"`
	CreatedAt time.Time     `bson:"createdAt"`
}

type MongoStore struct {
	client   *mongo.Client
	users    *mongo.Collection
	sessions *mongo.Collection
}

var _ Store = (*MongoStore)(nil)

func NewMongoStore(ctx context.Context, uri, dbName string) (*MongoStore, error) {
	// SetTimeout bounds every operation, even if a caller forgets a deadline.
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("connect mongo: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo: %w", err)
	}

	db := client.Database(dbName)
	s := &MongoStore{
		client:   client,
		users:    db.Collection("users"),
		sessions: db.Collection("sessions"),
	}
	if err := s.ensureIndexes(ctx); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, err
	}
	return s, nil
}

func (s *MongoStore) ensureIndexes(ctx context.Context) error {
	_, err := s.users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("users indexes: %w", err)
	}

	_, err = s.sessions.Indexes().CreateMany(ctx, []mongo.IndexModel{
		// TTL index: MongoDB deletes sessions once expiresAt passes.
		{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
		{Keys: bson.D{{Key: "userId", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("sessions indexes: %w", err)
	}
	return nil
}

func (s *MongoStore) CreateUser(ctx context.Context, username string, passwordHash []byte) (User, error) {
	doc := userDoc{
		ID:           bson.NewObjectID(),
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond), // BSON dates are millisecond precision
	}
	if _, err := s.users.InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return User{}, ErrUserExists
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return doc.toUser(), nil
}

func (s *MongoStore) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return s.findUser(ctx, bson.D{{Key: "username", Value: username}})
}

func (s *MongoStore) findUser(ctx context.Context, filter bson.D) (User, error) {
	var doc userDoc
	err := s.users.FindOne(ctx, filter).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find user: %w", err)
	}
	return doc.toUser(), nil
}

func (s *MongoStore) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	oid, err := bson.ObjectIDFromHex(userID)
	if err != nil {
		return "", fmt.Errorf("invalid user id: %w", err)
	}

	token := rand.Text() // 128 bits from crypto/rand
	now := time.Now().UTC()
	_, err = s.sessions.InsertOne(ctx, sessionDoc{
		ID:        hashToken(token),
		UserID:    oid,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	})
	if err != nil {
		return "", fmt.Errorf("insert session: %w", err)
	}
	return token, nil
}

func (s *MongoStore) SessionUser(ctx context.Context, token string) (User, error) {
	var sess sessionDoc
	// The TTL monitor runs about once a minute, so check expiry explicitly too.
	err := s.sessions.FindOne(ctx, bson.D{
		{Key: "_id", Value: hashToken(token)},
		{Key: "expiresAt", Value: bson.D{{Key: "$gt", Value: time.Now().UTC()}}},
	}).Decode(&sess)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find session: %w", err)
	}
	return s.findUser(ctx, bson.D{{Key: "_id", Value: sess.UserID}})
}

func (s *MongoStore) DeleteSession(ctx context.Context, token string) error {
	if _, err := s.sessions.DeleteOne(ctx, bson.D{{Key: "_id", Value: hashToken(token)}}); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *MongoStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx, nil)
}

func (s *MongoStore) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}
