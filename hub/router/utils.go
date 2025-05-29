/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package router

import "strings"

// extractTenantFromRawQuery extracts the tenant parameter from raw query string without URL decoding
func extractTenantFromRawQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	// Split by & to get individual parameters
	params := strings.Split(rawQuery, "&")
	for _, param := range params {
		// Split by = to get key and value
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 && parts[0] == "tenant" {
			return parts[1]
		}
	}

	return ""
}
