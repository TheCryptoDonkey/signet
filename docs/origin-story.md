# How Signet Happened

We're a group of friends who met at university more years ago than any of us would care to admit. A doctor, a solicitor, a computer scientist, and a humanities graduate — the setup sounds like the start of a bad joke, but we've stayed close over the decades. Different careers, different cities sometimes, but the kind of friendships where you pick up exactly where you left off.

Then we all became parents.

It's funny how that changes things. Suddenly the internet wasn't just a place where you argued about football and shared articles. It was the place your children were growing up in, and none of us were comfortable with what we saw. The conversations started happening naturally — over pints, on group chats, during those bleary-eyed late-night calls that parents know too well.

The doctor was seeing teenagers in crisis, struggling with things that happened to them online and having no way to verify who they'd been talking to. The solicitor was watching identity fraud cases multiply and professional credentials being faked with alarming ease. The computer scientist kept saying "we have the technology to fix this, we just haven't built it yet." And the humanities graduate — the one who always asked the awkward questions — kept pushing on what identity even *means* in a digital world, and who gets to decide.

We all had the same fear, coming from different directions: there is no reliable way to prove who is real online. Children can't tell if the adult they're talking to is who they claim to be. Professionals can't prove their credentials without handing over personal data. Deepfakes are making it worse by the month. And every solution anyone had proposed seemed to require trusting some central authority that would inevitably either fail or overreach.

So we did what any reasonable group of middle-aged professionals would do. We booked an Airbnb, found the nearest pub, and called it a reunion — with a mission this time, not on one. Every angle. The medical perspective on safeguarding. The legal requirements across jurisdictions. The technical constraints of cryptography and decentralised systems. The philosophical questions about privacy, autonomy, and what verification should and shouldn't mean. We argued about edge cases. We argued about naming things. We argued about whether we were overthinking it, and then we argued about whether we were underthinking it.

By Sunday evening, we had a document. It was messy and sprawling and covered in beer rings and questionable napkin diagrams, but it represented something none of us could have written alone — a genuinely interdisciplinary picture of the problem.

Then came the part that sounds a bit mad when you say it out loud.

We gave it all to Claude. About a hundred dollars' worth of tokens. We said, more or less: "Here's the problem from every angle we can think of. Don't stop until you've solved it. Go deep. Take your time. We'll wait."

And we waited.

What came back was Signet. A protocol for identity verification that uses zero-knowledge proofs so people can prove claims about themselves without revealing personal data. A system anchored to real-world professional bodies — the law societies, medical boards, and notary commissions that already verify identity — rather than to any new central authority. A design that handles everything from a child's age-appropriate access to a solicitor's professional credentials, all without creating a surveillance infrastructure.

None of us could have designed it alone. The doctor wouldn't have thought about the cryptographic primitives. The solicitor wouldn't have considered the selective disclosure mechanisms. The computer scientist wouldn't have mapped the professional verification landscape across jurisdictions. And the humanities graduate — well, they would have written a very thoughtful essay about the problem and then gone to the bar.

But together, we'd asked the right questions. That turned out to be the secret ingredient. The AI didn't need more computing power or a bigger model. It needed the right problems, stated precisely, from people who actually understood them from lived experience. A hundred dollars in tokens and four perspectives shaped by decades of professional practice and parenthood.

We're sharing Signet as an open protocol because the problems it addresses belong to everyone. No single company should own the solution to "how do we know who's real online." The spec is public. The code is open source. Anyone can build on it, improve it, or tell us where we got it wrong.

We started this because we were worried about our kids. We kept going because we realised the problem was bigger than any one family, any one profession, or any one country. Identity on the internet is broken, and it's going to take all of us — parents, professionals, builders, and yes, the occasional AI — to fix it.
