import os
import yaml
import time
import feedparser

from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIStix2Utils
from datetime import datetime
from stix2 import (
    Bundle,
    AttackPattern,
)

class TrendMicroConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.trendmicro_url = get_config_variable(
            "TRENDMICRO_URL", ["trendmicro", "trendmicro_url"], config, False
        )

        self.time_interval = get_config_variable(
            "TRENDMICRO_TIME_INTERVAL", ["trendmicro", "time_interval"], config, True
        )

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Trend Micro",
            description="CyberThread Data Import Connector",
        )["standard_id"]

    def get_interval(self) -> int:
        return int(self.time_interval) * 60 * 60 * 24

    def parseRssTrendMicroFeedToStix2Bundle(self, rssFeedTrendMicroUrl):
        rss_feed = feedparser.parse(rssFeedTrendMicroUrl)

        objectsList = []
        for entry in rss_feed.entries:
            dateTimeObj = datetime.strptime(entry.published[5: 25], '%d %b %Y %H:%M:%S')

            attack_pattern = AttackPattern(
                id=OpenCTIStix2Utils.generate_random_stix_id("attack-pattern"),
                name=entry.title,
                created= dateTimeObj.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                created_by_ref=self.identity,
                description=entry.description,
                external_references= [
                    {
                        "source_name": entry.title,
                        "url": entry.link
                    }
                ]
            )

            objectsList.append(attack_pattern)

        return Bundle(objects=objectsList, allow_custom=True).serialize()

    def run(self):
        self.helper.log_info("Fetching Trend_Micro datasets...")

        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info("Connector last run: " + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) > ((int(self.time_interval) - 1) * 60 * 60 * 24)):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Trend_Micro run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

                    # Try to send json data to OpenCTI platform
                    self.helper.log_info("Sending data to OpenCTI...")
                    try:
                        bundle = self.parseRssTrendMicroFeedToStix2Bundle(rssFeedTrendMicroUrl = self.trendmicro_url)
                        print(bundle)

                        self.helper.send_stix2_bundle(bundle)

                        # Store the current timestamp as a last run
                        message = "Connector successfully run, storing last_run as " + str(timestamp)
                        self.helper.log_info(message)
                        self.helper.set_state({"last_run": timestamp})
                        self.helper.api.work.to_processed(work_id, message)
                        self.helper.log_info("Last_run stored, next run in: " + str(round(self.get_interval() / 60 / 60 / 24, 2)) + " days")

                    except Exception as e:
                        self.helper.log_error(str(e))
                        print(e)

                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info("Connector will not run, next run in: " + str(round(new_interval / 60 / 60 / 24, 2)) + " days")
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        trendmicroConnector = TrendMicroConnector()
        trendmicroConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)