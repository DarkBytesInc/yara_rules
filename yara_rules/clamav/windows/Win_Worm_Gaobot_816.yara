rule Win_Worm_Gaobot_816
{
strings:
	$a0 = { ff518942f0a8419ab73bfae88fe22e5188742469bb082256ccb3be5f6cf0aa8c40d472d5e8c537934bee99137b63c0628661d588f3a4a99d59f412535c189f07b2a42b1735dc69da5c316e46b3bfc4fc4ce6ede2a856291c860e03af437c90922544a675ea5a45dea894220dd1 }

condition:
	$a0
}

        