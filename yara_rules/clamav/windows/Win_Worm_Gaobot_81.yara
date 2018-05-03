rule Win_Worm_Gaobot_81
{
strings:
	$a0 = { 4d790dd0718cebfa7e67be06ec1e59b9f25984604110fad07759e4d944ef64abd6ca072c73c0a419b0623c2c266392a0faae33bcbd4e67ef2c294f2d8b11d52c }

condition:
	$a0
}

        
