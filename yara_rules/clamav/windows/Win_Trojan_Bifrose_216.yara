rule Win_Trojan_Bifrose_216
{
strings:
	$a0 = { 4fb53ed4fb5336b7353353fdffdffe38ce79d8fefbf3ce7aebb08d42ca050615cf882e3e30bf0e400fa01a544b1253b978f072518120a44d7568998830ad02431c60becc091d9540f4a517b302bcf0c8198cdfd0c8845a3713b20a64fdbc2568f08e6e5c610c24a3c004dd712462c1f546d09536e419d0b81e070ea71d287d582a5abb7641097026646f76bb }

condition:
	$a0
}

        