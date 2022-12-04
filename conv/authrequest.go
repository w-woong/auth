package conv

import (
	"github.com/w-woong/auth/dto"
	"github.com/w-woong/auth/entity"
	"github.com/wonksing/structmapper"
)

func init() {
	structmapper.StoreMapper(&dto.AuthRequest{}, &entity.AuthRequest{})
	structmapper.StoreMapper(&entity.AuthRequest{}, &dto.AuthRequest{})
}

func ToAuthRequestEntity(input *dto.AuthRequest) (output entity.AuthRequest, err error) {
	err = structmapper.Map(input, &output)
	return
}

func ToAuthRequestDto(input *entity.AuthRequest) (output dto.AuthRequest, err error) {
	err = structmapper.Map(input, &output)
	return
}
