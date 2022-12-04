package adapter

import (
	"context"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
	"github.com/w-woong/common/logger"
	"github.com/w-woong/common/txcom"
	"gorm.io/gorm"
)

type authRequestPg struct {
	db *gorm.DB
}

func NewAuthRequestPg(db *gorm.DB) *authRequestPg {
	return &authRequestPg{
		db: db,
	}
}

func (a *authRequestPg) Create(ctx context.Context, tx common.TxController, authRequest entity.AuthRequest) (int64, error) {

	res := tx.(*txcom.GormTxController).Tx.WithContext(ctx).Create(&authRequest)
	if res.Error != nil {
		logger.Error(res.Error.Error())
		return 0, txcom.ConvertErr(res.Error)
	}

	return res.RowsAffected, nil
}
func (a *authRequestPg) Read(ctx context.Context, tx common.TxController, id string) (entity.AuthRequest, error) {
	return a.readAuthRequest(ctx, tx.(*txcom.GormTxController).Tx, id)
}
func (a *authRequestPg) ReadNoTx(ctx context.Context, id string) (entity.AuthRequest, error) {
	return a.readAuthRequest(ctx, a.db, id)
}
func (a *authRequestPg) Delete(ctx context.Context, tx common.TxController, id string) (int64, error) {
	res := tx.(*txcom.GormTxController).Tx.
		WithContext(ctx).
		Delete(&entity.AuthRequest{ID: id})
	if res.Error != nil {
		logger.Error(res.Error.Error())
		return 0, txcom.ConvertErr(res.Error)
	}
	return res.RowsAffected, nil
}

func (a *authRequestPg) readAuthRequest(ctx context.Context, db *gorm.DB, id string) (entity.AuthRequest, error) {
	authRequest := entity.AuthRequest{}
	res := db.WithContext(ctx).
		Where("id = ?", id).
		Limit(1).Find(&authRequest)

	if res.Error != nil {
		logger.Error(res.Error.Error())
		return entity.NilAuthRequest, txcom.ConvertErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return entity.NilAuthRequest, common.ErrRecordNotFound
	}

	return authRequest, nil
}
