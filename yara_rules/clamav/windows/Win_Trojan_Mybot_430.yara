rule Win_Trojan_Mybot_430
{
strings:
	$a0 = { a6a604651f1f96d44109b159498d13e0b339019633a3a3ea7fb1dae9277e70f1d564691072642589baa7eaa930580478ad4277f97d8feafaa10fddadb8e7ed85a60c04c84532cbb43f9aec0f249f646969e2334b441ca35e96395fcd4f280fd7a885c4e9c643deb93395576397a9853c2da7b0cf76d7ed0369059f194a903e273177bee69f2f6c02a8b7772a125deef88552c4e309 }

condition:
	$a0
}

        