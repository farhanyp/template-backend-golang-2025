package auth

import (
	"net/http"
	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/pkg/serverutils"

	"github.com/gin-gonic/gin"
)

type IAuthController interface {
	RegisterRoutes(r *gin.RouterGroup)
	Register(ctx *gin.Context)
}

type authController struct {
	service IAuthService
}

func NewAuthController(service IAuthService) IAuthController {
	return &authController{service: service}
}

func (c *authController) RegisterRoutes(r *gin.RouterGroup) {
	h := r.Group("/v1/auth")
	h.POST("/register", c.Register)
}

func (c *authController) Register(ctx *gin.Context) {
	var req dto.RegisterRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if err := serverutils.ValidateRequest(req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	res, err := c.service.Register(ctx.Request.Context(), &req)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.JSON(http.StatusOK, serverutils.SuccessResponse("Success Registration", res))
}
