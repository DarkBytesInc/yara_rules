rule Win_Ircbot_Antimarc_1
{
strings:
	$a0 = { 0d0a6e303d6f6e20313a434f4e4e4543543a207b0d0a6e313d2f6d7367206d617263204675436b20596f5520466153634973540d0a6e323d2f6d736720776172626c616465205354494c4c205355434b494e47204d415243277320434f434b3f3f2065682c207375726520796f7520646f21210d0a6e333d2f6d736720737570657220 }

condition:
	$a0
}

        