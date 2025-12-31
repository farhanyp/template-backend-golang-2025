package example

import (
	"net/http"

	"template-golang-2025/internal/dto"
	"template-golang-2025/internal/pkg/serverutils"

	"github.com/gin-gonic/gin"
)

type IExampleController interface {
	RegisterRoutes(r *gin.RouterGroup)
	HelloWorld(ctx *gin.Context)
}

type exampleController struct {
	service IExampleService
}

func NewExampleController(service IExampleService) IExampleController {
	return &exampleController{service: service}
}

func (c *exampleController) RegisterRoutes(r *gin.RouterGroup) {
	h := r.Group("/v1")
	h.POST("/hello-world", c.HelloWorld)
}

func (c *exampleController) HelloWorld(ctx *gin.Context) {
	var req dto.HelloWorldRequest

	// Bind JSON body
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Validation
	if err := serverutils.ValidateRequest(req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Call service (IMPORTANT PART)
	res, err := c.service.HelloWorld(ctx.Request.Context(), &req)
	if err != nil {
		// lempar ke global error handler gin
		ctx.Error(err)
		return
	}

	ctx.JSON(http.StatusOK, serverutils.SuccessResponse("Success", res))
}
