import logging, requests, time
from src.config import Config
from datetime import datetime
class ConnectionHandler:
    
    def __init__(self, pat = None, config_file = None):
        self.config = Config() if config_file is None else Config(config_file)
        self.headers = self.config.base_headers
        self.base_url = self.config.base_url
        if pat is not None:
            self.headers['Authorization'] = Config.generate_auth_header(pat)
    async def get(self, endpoint):
        resp = requests.get(self.base_url + endpoint, headers=self.headers, verify=False)
        if resp.status_code != 200:
            logging.warning(f'The response code for the GET endpoint {endpoint} is {resp.status_code}. Message: {resp.text}')
            await self.__validate_rate_limit(resp)
            resp = requests.get(self.base_url + endpoint, headers=self.headers, verify=True)
        try:
            return resp.json()
        except Exception:
            return {}
