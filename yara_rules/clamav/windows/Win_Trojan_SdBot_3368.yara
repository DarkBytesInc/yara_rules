rule Win_Trojan_SdBot_3368
{
strings:
	$a0 = { db56e2222472271ab0929dc8817bd127bf6d85ce1372fab0f4d5df5cc86ffb5cc16162c336fc3ce1f7af059486ed5f5a0018bfa10c4f7cb31b49b41f61bc75bbfe299dea487321698f3aacaeef3f135dd345ee0229f5c3cc31fd2d07c64c430fcc455ab9134a050432c3d69a218e4b73ca5ae96b6ae01c92bc6d57dfa5272dbc285752ba404a60d28ee6d2c2456dde4c75473f9ca7b7 }

condition:
	$a0
}

        