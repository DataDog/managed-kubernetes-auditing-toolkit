package eks

import (
	"github.com/spf13/cobra"
)

func BuildEksSubcommand() *cobra.Command {
	eksCommand := &cobra.Command{
		Use: "eks",
	}

	eksCommand.AddCommand(buildEksRoleRelationshipsCommand())
	eksCommand.AddCommand(buildEksFindSecretsCommand())

	return eksCommand
}
