rule Win_Trojan_Spambot_89
{
strings:
	$a0 = { 14e6747978ca162dbe91cd5f1dca7785d45dd724c19734f417ffcbf3162aae52c5d9d1b606ae219dffffffbf6dd7c0ba90938fc9e28eac490c8a50a59245faa26cecc8928ee6855077e2ffffff6e6c34b4f934a45216e6eeaf877ad28d331b51729465bd2eace4b6abfffffffbf9 }

condition:
	$a0
}

        
