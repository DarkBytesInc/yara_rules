rule Win_Trojan_Mybot_5158
{
strings:
	$a0 = { 062446f54e4bd2879e648d300461ea142160da886636321d6a0a0a0d4d1f0f583eecc334e2549711a2fa43741749327d3489865cd25eb43dfe4d4f41c628db5d691f9a9d737383cafe0db8501ed21cc2b43909f5f235838ede0dcf5b7e51c79f17e9a4968132d0bd9d761b3f54097813df9a767d88d65bd07bf21995a714c7ba }

condition:
	$a0
}

        