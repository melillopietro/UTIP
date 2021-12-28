import os
import yaml
import time
import traceback
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIStix2Utils
from stix2 import Bundle, Report, Vulnerability, Relationship, Identity, Note, ExternalReference
from datetime import datetime
from scrap.Scraper import Scraper
import json
from email.utils import parsedate_tz, mktime_tz

class TalosConnector:

    busy = False

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config) #errore
        self.talos_interval = get_config_variable(
            "TALOS_INTERVAL", ["talos", "interval"], config, True
        )

    def get_interval(self) -> int:
        return int(self.talos_interval) / 60 / 60 * 24


    def create_bundle(self, work_id):
        bundleObjectsz = []
        self.helper.log_info("CREATE BUNDLE CALLED")
        self.helper.log_info("WORK START")
        try:
            scraper = Scraper()
            scraper.scraping()
            identity = Identity(
                id=OpenCTIStix2Utils.generate_random_stix_id("identity"),
                name="TalosIntelligence"
            )

            #create bundle for zero day vulnerablity
            hand = scraper.zeroDayFileHandler()
            self.helper.log_info(hand)
            for line in hand:
                js = scraper.zeroDaySingle(line)
                if(js is None):
                    self.helper.log_info("Got None on line " + line)
                else:
                    j = json.loads(js)
                    timestamp = time.mktime(datetime.strptime(j["date"], "%Y-%m-%d %H:%M:%S").timetuple())
                    created = datetime.fromtimestamp(timestamp)
                    vulnerability = Vulnerability(
                        id = OpenCTIStix2Utils.generate_random_stix_id("vulnerability"),
                        name = j["id"],
                        created = created,
                        description = "zero day vulnerability",
                        labels=["ZeroDay", "Vulnerability"]
                    )
                    bundleObjectsz.append(identity)
                    bundleObjectsz.append(vulnerability)
            bundle = Bundle(objects=bundleObjectsz, allow_custom=True).serialize()
            self.helper.send_stix2_bundle(bundle, work_id=work_id)
            self.helper.log_info("ZERO DAY FINISH")
            bundleObjects = []
            #create bundle for discloseds vulnerability
            hand = scraper.disclosedsFileHandler()
            for line in hand:
                datas = scraper.disclosedsSingle(line)
                if(datas is None):
                    self.helper.log_info("Got None on line" + line)
                else:
                    data = json.loads(datas)
                    timestamp = time.mktime(datetime.strptime(data["date"], "%Y-%m-%d %H:%M:%S").timetuple())
                    pubDate = datetime.fromtimestamp(timestamp)
                    productUrl = ExternalReference(
                        url = data["product_urls"],
                        source_name = data["product_urls"],
                        description = "Product urls"
                    )
                    talosReport = ExternalReference(
                        url = data["report_url"],
                        description = "Talos Intelligence report",
                        source_name = "talosintelligence.com"
                    )
                    vulnerability = Vulnerability(
                        id = OpenCTIStix2Utils.generate_random_stix_id("vulnerability"),
                        name = data["cve_number"],
                        created_by_ref = identity.id,
                        description = data["short_description"]+"\n"+data["summary"],
                        labels = [
                            data["id"],
                            data["cvss_score"],
                            data["cwe"]
                        ],
                        external_references = [
                            productUrl,
                            talosReport
                        ]
                    )
                    note = Note(
                        id = OpenCTIStix2Utils.generate_random_stix_id("note"),
                        created = pubDate,
                        created_by_ref = identity.id,
                        content = data["timeline"],
                        abstract = "Timeline",
                        labels=["Talos Intelligence"],
                        object_refs=[vulnerability.id]
                    )
                    report = Report(
                        id = OpenCTIStix2Utils.generate_random_stix_id("report"),
                        report_types = ["vulnerablity"],
                        created_by_ref = identity.id,
                        name = data["id"],
                        published = pubDate,
                        labels=["vulnerability"],
                        object_refs=[vulnerability.id, note.id]
                    )
                    relationship = Relationship(
                        id = OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type = "related-to",
                        source_ref = vulnerability.id,
                        target_ref = report.id,
                        confidence = self.helper.connect_confidence_level
                    )
                    bundleObjects.append(identity)
                    bundleObjects.append(vulnerability)
                    bundleObjects.append(note)
                    bundleObjects.append(report)
                    bundleObjects.append(relationship)
            bundle = Bundle(objects=bundleObjects, allow_custom=True).serialize()
            self.helper.send_stix2_bundle(bundle, work_id=work_id)
            self.helper.log_info("DISCLOSEDS FINISH")
        except Exception as e:
            self.helper.log_info(e)
            self.helper.log_info(traceback.format_exc())

    def process_data(self):
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval-1 day
            if last_run is None or (
                (timestamp - last_run) > ((int(self.talos_interval) - 1)  / 60 / 60 * 24)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "Talos Connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.create_bundle(work_id)
                # Store the current timestamp as a last run
                self.helper.log_info(
                    "Connector successfully run, storing last_run as " + str(timestamp)
                )
                self.helper.set_state({"last_run": timestamp})
                message = (
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60 / 24, 2))
                    + " days"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60 / 24, 2))
                    + " days"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching Talos intelligence data...")
        while True:
            self.process_data()
            time.sleep(3600)

if __name__ == "__main__":
    try:
        connector = TalosConnector() #errore
        connector.run()
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        time.sleep(10)
        exit(0)
