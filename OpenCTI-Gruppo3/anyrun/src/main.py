import os
from threading import Thread

import yaml
import time

from pycti import OpenCTIConnectorHelper
from anyrun.client import AnyRunClient

class AnyRun:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"

        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.descriptionEnrichment = "This malware family has been executed on an AnyRun sandbox"
        self.clientMalwareInfo = []
        self.helper = OpenCTIConnectorHelper(config)

    def callback(self, dict: dict) -> None:
        if("collection" in dict and dict["collection"] == "statistics.day.tags"):
            self.clientMalwareInfo.append(dict["fields"]["tag"])

    def _process_message(self, data):
        entity_id = data["entity_id"]
        entity = self.helper.api.stix_domain_object.read(id=entity_id)

        if(entity is None):
            raise ValueError("Entity not found")
        else:
            self.helper.log_info("Stix Domain Object detected. Check if it's malware")

            if(entity["entity_type"].lower() == "malware"):
                self.helper.log_info("Malware detected. Check if already on the platform")

                for tag in self.clientMalwareInfo:
                    if (tag.lower() == entity["name"].lower() or tag.lower() in (malwareType.lower() for malwareType in entity["malware_types"])):
                        self.helper.log_info("Malware info already are on OpenCTI")

                        if (self.descriptionEnrichment in entity["description"]):
                            return "Malware already enriched"
                        else:
                            newDescription = entity["description"] + "\n\n" + self.descriptionEnrichment
                            self.helper.api.stix_domain_object.update_field(
                                id=entity["id"],
                                input={"key": "description", "value": newDescription},
                            )

                            return "The malware has been enriched"

    def startClient(self):
        self.client = AnyRunClient(
            on_message_cb=self.callback,
            enable_trace=False
        )

        self.client.connect()
        self.client.run_forever()

    # Start the main loop
    def start(self):
        while(len(self.clientMalwareInfo) == 0):
            time.sleep(10)

        self.helper.listen(self._process_message)

if __name__ == "__main__":
    try:
        anyrunConnector = AnyRun()
        Thread(target=anyrunConnector.startClient).start()
        anyrunConnector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)