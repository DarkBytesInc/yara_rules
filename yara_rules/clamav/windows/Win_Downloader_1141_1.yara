rule Win_Downloader_1141_1
{
strings:
	$a0 = { 3c0c17c9cde884ab83670bb6171fea1b4b507305495650e90d5f4f963eb1a6bb1514fc3ee24bdbe7f21580f1b013fce1ca69cee616e064e923f2c4b166300a93c8edb3957e320eb229e312fc8ddc7ec40f90ed46fb0cfc099d74b623 }

condition:
	$a0
}

        
