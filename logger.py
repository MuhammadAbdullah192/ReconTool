import logging
logger = logging.getLogger("ReconTool")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler("recon.log")
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

report_file = "recon_report.txt"