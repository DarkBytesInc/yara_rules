rule Win_Worm_Stration_432
{
strings:
	$a0 = { 30449f089432e96b2fc45f55289dcbd2c62d1969892accb07844fdd83bf8b3cf35a389adee66ae4cff5d7b7819d46c286146182258209d68658cbec401fbb892b40173eac9967fc1f791c40f5da68d73 }

condition:
	$a0
}

        
