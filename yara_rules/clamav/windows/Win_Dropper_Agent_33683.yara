rule Win_Dropper_Agent_33683
{
strings:
	$a0 = { 52dff51a36de35e6bcd835c8e7ca3abc654d8e9e587b2243d3f912943297db65b3c3c4b84840d56e820c8ec2c93327c0b0dd8562e31817ef92274663f6fe847ce7791f1919a577510982366e56d539fb1e4404443d0210cb9dea09ded50833b1ca60c946235e6d8e5a6ef75072ca631414ed5504d8805b93181a04f71b04b5645624470bf00dc680b28863a05d5d552847936ef4 }

condition:
	$a0
}

        