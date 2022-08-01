// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package apis

import (
	"context"

	"github.com/l3af-project/l3afd/apis/handlers"
	"github.com/l3af-project/l3afd/kf"
	"github.com/l3af-project/l3afd/routes"
)

func apiRoutes(ctx context.Context, kfcfg *kf.NFConfigs) []routes.Route {

	r := []routes.Route{
		{
			Method:      "POST",
			Path:        "/l3af/configs/{version}/update",
			HandlerFunc: handlers.UpdateConfig(ctx, kfcfg),
		},
		{
			Method:      "GET",
			Path:        "/l3af/configs/{version}/{iface}",
			HandlerFunc: handlers.GetConfig,
		},
		{
			Method:      "GET",
			Path:        "/l3af/configs/{version}",
			HandlerFunc: handlers.GetConfigAll,
		},
		{
			Method:      "POST",
			Path:        "/l3af/configs/{version}/add",
			HandlerFunc: handlers.AddEbpfPrograms(ctx, kfcfg),
		},
		{
			Method:      "POST",
			Path:        "/l3af/configs/{version}/delete",
			HandlerFunc: handlers.DeleteEbpfPrograms(ctx, kfcfg),
		},
	}

	return r
}
