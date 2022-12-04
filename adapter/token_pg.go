package adapter

import (
	"context"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
	"github.com/w-woong/common/logger"
	"github.com/w-woong/common/txcom"
	"gorm.io/gorm"
)

type tokenPg struct {
	db *gorm.DB
}

func NewTokenPg(db *gorm.DB) *tokenPg {
	return &tokenPg{
		db: db,
	}
}

func (a *tokenPg) Create(ctx context.Context, tx common.TxController, token entity.Token) (int64, error) {

	res := tx.(*txcom.GormTxController).Tx.WithContext(ctx).Create(&token)
	if res.Error != nil {
		logger.Error(res.Error.Error())
		return 0, txcom.ConvertErr(res.Error)
	}

	return res.RowsAffected, nil
}

func (a *tokenPg) Read(ctx context.Context, tx common.TxController, id string) (entity.Token, error) {
	return a.readToken(ctx, tx.(*txcom.GormTxController).Tx, id)
}

func (a *tokenPg) ReadNoTx(ctx context.Context, id string) (entity.Token, error) {
	return a.readToken(ctx, a.db, id)
}

func (a *tokenPg) Delete(ctx context.Context, tx common.TxController, id string) (int64, error) {
	res := tx.(*txcom.GormTxController).Tx.
		WithContext(ctx).
		Delete(&entity.Token{ID: id})
	if res.Error != nil {
		logger.Error(res.Error.Error())
		return 0, txcom.ConvertErr(res.Error)
	}
	return res.RowsAffected, nil
}

func (a *tokenPg) readToken(ctx context.Context, db *gorm.DB, id string) (entity.Token, error) {
	token := entity.Token{}
	res := db.WithContext(ctx).
		Where("id = ?", id).
		Limit(1).Find(&token)

	if res.Error != nil {
		logger.Error(res.Error.Error())
		return entity.NilToken, txcom.ConvertErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return entity.NilToken, common.ErrRecordNotFound
	}

	return token, nil
}
