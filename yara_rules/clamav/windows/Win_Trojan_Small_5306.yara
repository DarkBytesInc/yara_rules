rule Win_Trojan_Small_5306
{
strings:
	$a0 = { 50c89db1e83472f9ebdf89f4acf8df70c020dac752e1dcd9d0f3c9713dc8fb74e8df0c3501dffe9500df9f79f81f8ad0463de5caab36e1d9e8ef897152e8888620f0c97138df9fadf81f8afcd84a8adb0b36f471e7f5dd8128e00e315d1215ae18f0c9713edf61f6a854afc7e7b70aed18dfe6 }

condition:
	$a0
}

        
