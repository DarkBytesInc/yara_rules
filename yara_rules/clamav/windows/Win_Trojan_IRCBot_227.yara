rule Win_Trojan_IRCBot_227
{
strings:
	$a0 = { 89bec8a6e3d5f1b1e5ee4f704cdeaa1f496a4c2f3b7b4dba9dc895d6e5f4037adc3cf00e2356d1226abf86ad4d865b80794cd266c8487946bfe5509f9edbcb227df07b3962f1f913a5e4bc4eb13fb68cdee85b710fa0f5021f54992136403fcd4fca53ffaa657752d5da94cc2392ffdb852d567dc8f7753d39170f72335fee2b890f529948346cec21efa67a9c2ec0bc9c9538fc8cf1 }

condition:
	$a0
}

        