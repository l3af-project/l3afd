// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package apis

import (
	"context"

	"github.com/l3af-project/l3afd/v2/apis/handlers"
	"github.com/l3af-project/l3afd/v2/bpfprogs"
	"github.com/l3af-project/l3afd/v2/routes"
)

func apiRoutes(ctx context.Context, bpfcfg *bpfprogs.NFConfigs) []routes.Route {

	r := []routes.Route{
		{
			Method:      "POST",
			Path:        "/l3af/configs/{version}/update",
			HandlerFunc: handlers.UpdateConfig(ctx, bpfcfg),
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
			HandlerFunc: handlers.AddEbpfPrograms(ctx, bpfcfg),
		},
		{
			Method:      "POST",
			Path:        "/l3af/configs/{version}/delete",
			HandlerFunc: handlers.DeleteEbpfPrograms(ctx, bpfcfg),
		},
		{
			Method:      "PUT",
			Path:        "/l3af/configs/{version}/restart",
			HandlerFunc: handlers.HandleRestart(ctx, bpfcfg),
		},
	}

	return r
}
