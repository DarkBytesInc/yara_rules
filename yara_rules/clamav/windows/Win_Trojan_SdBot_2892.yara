rule Win_Trojan_SdBot_2892
{
strings:
	$a0 = { 6d7a07eb6b655430f9bf644bcee575f8c10a6a5e81c20c65dffdfa8e06cf27dbd53283803ef41cb8f6de95eb846ca58a405080b0c490fdca0018b2810920fb9b0e32942c77757e3162a686a3034594f29fd215420639895e1b8f0df644aaf648f037d353151198177b6c879ef082565032ece5f8da56c977944e25cacf92b8ed63da6dab855d05347f911706d809cbe4d06aea95d28b }

condition:
	$a0
}

        