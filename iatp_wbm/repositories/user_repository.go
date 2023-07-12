package repositories

import (
	"context"
	"iatp/cache"
	"iatp/setting"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	UserName    string             `json:"user_name" bson:"user_name"`
	FailureTime time.Time          `json:"failure_time" bson:"failure_time"`
}

type UserRepository interface {
	SearchByName(name string) []User
	InsertOne(name string) bool
	DeleteOne(name string) bool
	SearchActivity(filter bson.M) []cache.SuccessLogonCache
}

type userMemoryRepository struct {
	mu sync.RWMutex
}

func NewUserRepository() UserRepository {
	return &userMemoryRepository{}
}

func (m *userMemoryRepository) SearchByName(name string) []User {
	var filter bson.M

	if name == "" {
		filter = bson.M{}
	} else {
		filter = bson.M{"user_name": name}
	}

	var users []User

	err := setting.WbmUserMongo.FindAll(filter).All(context.TODO(), &users)

	if err != nil {
		return nil
	}

	return users
}

func (m *userMemoryRepository) InsertOne(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := m.SearchByName(name)
	if result != nil {
		return false
	}

	u := User{
		ID:          primitive.NewObjectID(),
		UserName:    name,
		FailureTime: time.Now().Add(24 * time.Hour * 1024),
	}

	r := setting.WbmUserMongo.InsertOne(u)

	return r.InsertedID != nil
}

func (m *userMemoryRepository) DeleteOne(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	r := setting.WbmUserMongo.DeleteOne(bson.M{"user_name": name})

	return r.DeletedCount > 0
}

func (m *userMemoryRepository) SearchActivity(filter bson.M) []cache.SuccessLogonCache {
	var activity []cache.SuccessLogonCache = make([]cache.SuccessLogonCache, 0)

	err := setting.CacheMongo.FindAll(filter).All(context.TODO(), &activity)
	if err != nil {
		return activity
	}

	return activity
}
