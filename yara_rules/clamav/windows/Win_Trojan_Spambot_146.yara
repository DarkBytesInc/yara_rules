rule Win_Trojan_Spambot_146
{
strings:
	$a0 = { 5ebef7d83dcb89fb038b22cb41f233df9448576df5de854c7dfffff1d1a4cd3f872102292e1ed178c912bf9724873cccd0ffffffff75f36650a12cbc31592226e33d0f2b85c39953ec2532b6a32523e64c9888d359abffffff64c0da64e483d6ae85aeec177ffae1dace0add28bf }

condition:
	$a0
}

        
