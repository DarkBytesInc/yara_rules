rule Win_Trojan_Spambot_166
{
strings:
	$a0 = { ff587e0cfffffffff02f18dbe3f567bd5c6eaa18a0f9e457831ca43b5e46a39e1ab5082091d18408faffffff0946083b81c882bd364f67ed334609dce4a11dd0a2b101a510cf009191ffffffbfd306c622978d35ba0ed103acf958a6582aba0b34fd2fb4f69dd2a8a6b7abffffff }

condition:
	$a0
}

        
