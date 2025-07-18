/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package api

import (
	"GADS/common/models"

	"github.com/gin-gonic/gin"
)

func GenericResponse(c *gin.Context, statusCode int, message string, result interface{}) {
	c.JSON(statusCode, models.APIResponse{
		Message: message,
		Result:  result,
	})
}
