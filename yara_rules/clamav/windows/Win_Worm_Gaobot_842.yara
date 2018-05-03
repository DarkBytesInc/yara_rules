rule Win_Worm_Gaobot_842
{
strings:
	$a0 = { 067df029a61b1ec5bb1c058e40f0bc6a6c3283a836c0c788aac3f8ae26edab6a66de918891eb5c792eec6edf27b9e17934bd20616662e3db60c1cdcb73d869aea065c1d579cab4e4aba572cec9502eb4e326a2124f07c1a4a075280f4d1bb7e5c35317bcc02311b4c49a191e4d }

condition:
	$a0
}

        
