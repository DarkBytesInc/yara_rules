rule Win_Worm_Gaobot_598
{
strings:
	$a0 = { 18b6797c44f0b584e10cbdf2f058a41b01a0052d222f93ebd0c24101e3ac775e65b71be410f700194c33705fb22bdef0a53c60c41e56ca80cbd0dc396aae0023f46bec8e3f5b220030793a }

condition:
	$a0
}

        
