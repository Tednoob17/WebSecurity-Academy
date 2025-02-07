## What is CSRF?

Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induice users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.


## How does CSRF work?

For a CSRF attack to be possible, three key conditions must be in place:
- **A relevant  action** : This is a action who an permit to attacker to perform a priviledge action (like change admin password)
- **Cookie-based session handling** : 