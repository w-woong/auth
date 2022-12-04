package adapter

import (
	"context"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
	"github.com/w-woong/common/logger"
	"github.com/w-woong/common/txcom"
	"gorm.io/gorm"
)

type authStatePg struct {
	db *gorm.DB
}

func NewAuthStatePg(db *gorm.DB) *authStatePg {
	return &authStatePg{
		db: db,
	}
}

func (a *authStatePg) Create(ctx context.Context, tx common.TxController, authState entity.AuthState) (int64, error) {

	res := tx.(*txcom.GormTxController).Tx.WithContext(ctx).Create(&authState)
	if res.Error != nil {
		logger.Error(res.Error.Error())
		return 0, txcom.ConvertErr(res.Error)
	}

	return res.RowsAffected, nil
}

// Read(id string) (entity.AuthState, error)
func (a *authStatePg) ReadByState(ctx context.Context, tx common.TxController, state string) (entity.AuthState, error) {
	return a.readByState(ctx, tx.(*txcom.GormTxController).Tx, state)
}

// Delete(id string) (int64, error)
func (a *authStatePg) DeleteByState(ctx context.Context, tx common.TxController, state string) (int64, error) {
	res := tx.(*txcom.GormTxController).Tx.
		WithContext(ctx).
		Delete(&entity.AuthState{State: state})
	if res.Error != nil {
		logger.Error(res.Error.Error())
		return 0, txcom.ConvertErr(res.Error)
	}
	return res.RowsAffected, nil
}

func (a *authStatePg) readByState(ctx context.Context, db *gorm.DB, state string) (entity.AuthState, error) {
	authState := entity.AuthState{}
	res := db.WithContext(ctx).
		Where("state = ?", state).
		Limit(1).Find(&authState)

	if res.Error != nil {
		logger.Error(res.Error.Error())
		return entity.NilAuthState, txcom.ConvertErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return entity.NilAuthState, common.ErrRecordNotFound
	}

	return authState, nil
}
