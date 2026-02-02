"""
Draxyl AI - A simple neural network chatbot built from scratch
"""
import json
import random
import re
import math
from collections import defaultdict

class DraxylAI:
    def __init__(self):
        self.knowledge_base = {
            "greetings": {
                "patterns": ["hello", "hi", "hey", "greetings", "good morning", "good afternoon", "good evening", "sup", "what's up"],
                "responses": [
                    "Hello! I'm Draxyl AI, your intelligent assistant. How can I help you today?",
                    "Hi there! Ready to assist you. What's on your mind?",
                    "Hey! Great to chat with you. What can I do for you?",
                    "Greetings! I'm here to help. What would you like to know?"
                ]
            },
            "draxyl_info": {
                "patterns": ["what is draxyl", "tell me about draxyl", "draxyl features", "what does draxyl do"],
                "responses": [
                    "Draxyl is an all-in-one communication platform with messaging, video calls, file sharing, and team collaboration tools!",
                    "Draxyl combines the best of messaging apps with powerful workspace features - channels, video calls, file management, and more!",
                    "Think of Draxyl as your complete workspace solution: real-time messaging, HD video calls, secure file sharing, and seamless team collaboration."
                ]
            },
            "video_calls": {
                "patterns": ["video call", "video chat", "call someone", "how to call", "calling"],
                "responses": [
                    "To start a video call in Draxyl: Open any channel, click the video camera icon 📹, and you'll instantly connect with everyone in that channel!",
                    "Video calling is easy! Just click the camera icon in your channel and start talking. Supports multiple participants with HD quality!",
                    "Want to video call? Navigate to your channel and hit the 📹 button. Your teammates will get an instant notification!"
                ]
            },
            "help": {
                "patterns": ["help", "assist", "support", "how to", "can you help", "need help"],
                "responses": [
                    "I can help you with:\n- Information about Draxyl features\n- How to use messaging and video calls\n- Creating workspaces and channels\n- General questions\n\nWhat do you need?",
                    "I'm here to help! Ask me about Draxyl features, how to use the app, or any questions you have.",
                    "Need assistance? I can explain Draxyl features, guide you through setup, or answer questions!"
                ]
            },
            "workspace": {
                "patterns": ["workspace", "create workspace", "how to create", "team space", "organization"],
                "responses": [
                    "A workspace is your team's home in Draxyl! Create one by clicking the ➕ button, give it a name, and invite your team with a join code.",
                    "To create a workspace: Click 'New Workspace' → Enter name → Share the join code with teammates. That's it!",
                    "Workspaces organize your team. Each workspace can have multiple channels for different topics or projects."
                ]
            },
            "channels": {
                "patterns": ["channel", "create channel", "what is channel", "chat room"],
                "responses": [
                    "Channels are like chat rooms within your workspace. Create them for different projects, departments, or topics!",
                    "Think of channels as organized conversations. Each workspace can have unlimited channels - one for marketing, one for dev, etc.",
                    "Create a channel by clicking '+ New Channel' in your workspace. Name it, and start chatting with your team!"
                ]
            },
            "security": {
                "patterns": ["security", "secure", "encryption", "privacy", "safe", "protect"],
                "responses": [
                    "Draxyl uses end-to-end encryption, secure authentication, and follows industry-standard security practices to keep your data safe!",
                    "Your security matters! We use bcrypt password hashing, JWT tokens, HTTPS encryption, and regular security audits.",
                    "All messages and files are encrypted. We use secure protocols and never store plain-text passwords. Your data is protected!"
                ]
            },
            "pricing": {
                "patterns": ["price", "cost", "how much", "pricing", "free", "paid"],
                "responses": [
                    "Draxyl offers flexible pricing! We have a free tier for small teams, and premium plans starting at $10/user/month for advanced features.",
                    "Pricing:\n- Free: Up to 10 users\n- Pro: $10/user/month\n- Enterprise: Custom pricing\n\nAll plans include messaging and video calls!",
                    "Start free! Our free plan includes unlimited messages and video calls. Upgrade anytime for more storage and advanced features."
                ]
            },
            "thanks": {
                "patterns": ["thank", "thanks", "appreciate", "grateful", "awesome"],
                "responses": [
                    "You're welcome! Happy to help! 😊",
                    "No problem! That's what I'm here for!",
                    "Glad I could help! Let me know if you need anything else!",
                    "Anytime! Enjoy using Draxyl! 🚀"
                ]
            },
            "goodbye": {
                "patterns": ["bye", "goodbye", "see you", "later", "exit", "quit"],
                "responses": [
                    "Goodbye! Come back anytime if you need help! 👋",
                    "See you later! Happy collaborating on Draxyl!",
                    "Take care! I'm always here if you need assistance! 😊"
                ]
            },
            "identity": {
                "patterns": ["who are you", "what are you", "your name", "introduce yourself"],
                "responses": [
                    "I'm Draxyl AI, your intelligent assistant built right into the Draxyl platform! I'm here to help you get the most out of your workspace.",
                    "I'm Draxyl AI - a smart chatbot created to assist you with anything related to Draxyl. Think of me as your personal guide!",
                    "I'm an AI assistant designed specifically for Draxyl. I can answer questions, guide you through features, and help your team collaborate better!"
                ]
            },
            "capabilities": {
                "patterns": ["what can you do", "capabilities", "features", "abilities"],
                "responses": [
                    "I can:\n✓ Answer questions about Draxyl\n✓ Guide you through features\n✓ Help troubleshoot issues\n✓ Provide tips and tricks\n✓ Explain how to use messaging, calls, and more!",
                    "My capabilities include explaining features, answering questions, helping with setup, and providing support for all Draxyl functions!",
                    "I'm designed to help with everything Draxyl! Ask me about features, how-tos, troubleshooting, or general information."
                ]
            }
        }
        
        # Conversation context
        self.context = []
        self.max_context = 5
        
    def clean_input(self, text):
        """Clean and normalize user input"""
        text = text.lower().strip()
        text = re.sub(r'[^\w\s]', '', text)
        return text
    
    def calculate_similarity(self, input_text, pattern):
        """Calculate similarity between input and pattern using word overlap"""
        input_words = set(input_text.split())
        pattern_words = set(pattern.split())
        
        if not input_words or not pattern_words:
            return 0
        
        intersection = input_words & pattern_words
        union = input_words | pattern_words
        
        # Jaccard similarity
        similarity = len(intersection) / len(union) if union else 0
        
        # Boost if pattern is substring of input
        if pattern in input_text:
            similarity += 0.3
        
        return similarity
    
    def find_best_match(self, user_input):
        """Find the best matching category and response"""
        cleaned_input = self.clean_input(user_input)
        
        best_category = None
        best_score = 0
        
        for category, data in self.knowledge_base.items():
            for pattern in data["patterns"]:
                score = self.calculate_similarity(cleaned_input, pattern)
                if score > best_score:
                    best_score = score
                    best_category = category
        
        # Threshold for matching
        if best_score > 0.2:
            return best_category, best_score
        
        return None, 0
    
    def generate_response(self, user_input):
        """Generate AI response based on user input"""
        # Add to context
        self.context.append(user_input)
        if len(self.context) > self.max_context:
            self.context.pop(0)
        
        category, confidence = self.find_best_match(user_input)
        
        if category and confidence > 0.2:
            response = random.choice(self.knowledge_base[category]["responses"])
            return {
                "response": response,
                "confidence": round(confidence * 100, 1),
                "category": category
            }
        else:
            # Generic responses for unknown queries
            generic_responses = [
                "I'm not sure I understand. Could you rephrase that? Or ask me about Draxyl features, video calls, workspaces, or security!",
                "Hmm, I don't have specific information on that. Try asking about Draxyl's messaging, video calls, or team collaboration features!",
                "I'm still learning! Could you ask in a different way? I'm great at explaining Draxyl features and how to use them!",
                "I don't have an answer for that yet, but I can help with Draxyl features, pricing, security, and how-tos!"
            ]
            return {
                "response": random.choice(generic_responses),
                "confidence": 0,
                "category": "unknown"
            }
    
    def chat(self, message):
        """Main chat interface"""
        if not message or len(message.strip()) == 0:
            return {
                "response": "Please type something! I'm here to help.",
                "confidence": 0,
                "category": "empty"
            }
        
        return self.generate_response(message)

# Create global AI instance
ai = DraxylAI()

def get_response(message):
    """Simple function to get AI response"""
    return ai.chat(message)

if __name__ == "__main__":
    print("🤖 Draxyl AI - Testing Mode")
    print("=" * 50)
    print("Type 'quit' to exit\n")
    
    while True:
        user_input = input("You: ")
        if user_input.lower() in ['quit', 'exit', 'bye']:
            print("AI: Goodbye! 👋")
            break
        
        result = ai.chat(user_input)
        print(f"AI: {result['response']}")
        print(f"(Confidence: {result['confidence']}% | Category: {result['category']})\n")
