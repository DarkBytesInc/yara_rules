rule Win_Trojan_Mybot_5661
{
strings:
	$a0 = { 4a69a466c217dfba59ed722acb0bc85d4f4eadc7564df208d65285438c14183f4290d10d573aac71eb16f96166f86d1742a2db228cb911f5e562abded3405c7a7377fd1c52ce813bcf4918ed38065923923c24207dfed20af684ebbc6ac91cb91d0d390c06374116462ee5089f3b96435a1bd1d7b55ca142647c5dd5077a }

condition:
	$a0
}

        