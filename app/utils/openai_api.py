import os

import requests
import os
import openai
from openai import OpenAI

class OpenAiApi(object):

    API_URL = 'https://api.openai.com/v1/engines/davinci-codex/completions'
    gpt_model=['gpt-3.5-turbo', "gpt-4", 'gpt-4o', "davinci-codex"]
    
    client = OpenAI(api_key=os.environ['OPEN_AI_API_KEY'])  # this is also the default, it can be omitted
    header: int =1

    def send_request(self, *, prompt: str, tokens: int, temperature: int=0)-> any:
        match self.header:
            case 1:
                response = self.client.chat.completions.create( #openai.Completion.create(
                    model=self.gpt_model[2],  # Use GPT-4 for better results
                    prompt=prompt,
                    max_tokens=tokens # 200
                )
                
            case 2:
                messages = [{"role": "user", "content": prompt}]                
                                
                response = self.client.chat.completions.create(model=self.gpt_model[2], messages=messages, temperature=temperature)
                """ return completion.choices[0].message["content"] """
                
            case 3:
                response = self.client.chat.completions.create(
                    engine=self.gpt_model[2],
                    prompt=prompt,
                    max_tokens=tokens
                )
                
            case 4:
                # Generate optimized CV using ChatGPT
                response = self.client.chat.completions.create(
                    model=self.gpt_model[2],
                    messages=[
                        {"role": "system", "content": "You are a professional CV optimization specialist."},
                        {"role": "user", "content": prompt }
                    ]
                )                
            case 5:
                response = self.client.beta.assistants.create(
                    name="Recruiter and CV specialist",
                    instructions=prompt,
                    tools=[{"type": "code_interpreter"}],
                    model="gpt-4o",
                )
            case 6:
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a professional CV optimization specialist.",
                        },
                        {
                            "role": "user",
                            "content": "Task, Goal, or Current Prompt:\n" + prompt,
                        },
                    ],
                )
        return response
    #
    def request_with_model_4(self, *, tokens:int=100, prompt: str=None):

        if not prompt or prompt is None:
            raise ValueError("No prompt provided")
        elif not tokens or tokens is None:
            raise ValueError("No tokens provided")
        
        try:
            self.header=6
            #response = self.send_request(prompt=prompt, tokens=tokens)
            #return True, response.choices[0].text.strip()
            response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a professional CV optimization specialist.",
                        },
                        {
                            "role": "user",
                            "content": "Task, Goal, or Current Prompt:\n" + prompt,
                        },
                    ],
                    #timeout=30  # Timeout after 15 seconds
                )
            return True, response.choices[0].message.content
        except Exception as e:
            return False, str(e)

    def code_assistant(self, tokens: int = 50, prompt: str = None):
        if not prompt or prompt is None or prompt=='':
            raise ValueError("No prompt provided")
        elif not tokens or tokens is None:
            raise ValueError("No tokens provided")
        
        try:
            self.header=3
            response = self.send_request(prompt=prompt, tokens=tokens)
            return True, response.choices[0].text.strip()
        except Exception as e:
            return False, str(e)