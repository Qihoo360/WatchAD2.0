package services

import (
	"iatp/cache"
	"iatp/iatp_wbm/repositories"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserService interface {
	// 根据用户名获取资产信息
	SearchByName(name string) (result []repositories.User)
	InsertUser(name string) bool
	DeleteUser(name string) bool
	SearchActivity(user_name string, logon_source string, input_datetime_range string) []cache.SuccessLogonCache
}

type userService struct {
	repo repositories.UserRepository
}

func NewUserService(repo repositories.UserRepository) UserService {
	return &userService{
		repo: repo,
	}
}

func (s *userService) SearchByName(name string) (result []repositories.User) {
	return s.repo.SearchByName(name)
}

func (s *userService) InsertUser(name string) bool {
	return s.repo.InsertOne(name)
}

func (s *userService) DeleteUser(name string) bool {
	return s.repo.DeleteOne(name)
}

func (s *userService) SearchActivity(user_name string, logon_source string, input_datetime_range string) []cache.SuccessLogonCache {
	filter := bson.M{}

	var activities = make([]cache.SuccessLogonCache, 0)

	if user_name == "" && logon_source == "" {
		return activities
	}

	if user_name != "" {
		filter["who"] = bson.M{
			"$regex": primitive.Regex{Pattern: user_name, Options: "i"},
		}
	}

	if logon_source != "" {
		filter["$or"] = []bson.M{
			{"from_host": bson.M{
				"$regex": primitive.Regex{Pattern: logon_source, Options: "i"},
			}},
			{"from_address": bson.M{
				"$regex": primitive.Regex{Pattern: logon_source, Options: "i"},
			}},
		}
	}

	start_time, _ := strconv.Atoi(strings.Split(input_datetime_range, ",")[0])
	end_time, _ := strconv.Atoi(strings.Split(input_datetime_range, ",")[1])
	filter["when"] = bson.M{"$gte": unix2time(int64(start_time)), "$lte": unix2time(int64(end_time))}

	users_activity := s.repo.SearchActivity(filter)

	for k := range users_activity {
		users_activity[k].When = users_activity[k].When.Add(8 * time.Hour)
	}

	return users_activity
}
