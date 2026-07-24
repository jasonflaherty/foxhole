package cli

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jasonflaherty/foxhole/internal/api"
	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func newServeCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Foxhole REST API and dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Flags())
			_ = v.BindPFlags(cmd.Root().PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			addr, _ := cmd.Flags().GetString("addr")
			database, err := db.Open(expandPath(cfg.DBPath))
			if err != nil {
				return err
			}
			defer func() { _ = database.Close() }()

			if err := ensurePhase2Data(cmd.Context(), database); err != nil {
				return err
			}

			srv := &api.Server{
				DB:         database,
				Cfg:        cfg,
				SeedPhase2: ensurePhase2Data,
			}
			handler := srv.NewRouter()
			httpSrv := &http.Server{
				Addr:              addr,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
			}
			logger.L().Info("foxhole API listening", zap.String("addr", addr))
			display := addr
			if len(addr) > 0 && addr[0] == ':' {
				display = "localhost" + addr
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Foxhole API + dashboard on http://%s\n", display)
			return httpSrv.ListenAndServe()
		},
	}
	cmd.Flags().String("addr", ":8080", "listen address")
	return cmd
}
