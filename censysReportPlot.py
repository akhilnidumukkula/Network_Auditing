import censys.ipv4
from constants import CENSYS_API_ID, CENSYS_API_SECRET, IP_RANGE
import plotly.graph_objects as graph


censysHandle = censys.ipv4.CensysIPv4(api_id=AKHIL_API_ID, api_secret=AKHIL_API_SECRET)

for subnet in IP_RANGE:
    osList = []
    osCount = []
    websrv80List = []
    websrv80Count = []
    websrv8080List = []
    websrv8080Count = []
    websrv8888List = []
    websrv8888Count = []
    protocolList = []
    protocolCount = []
    poodleHostList = []
    poodleHostCount = []

    osReport = censysHandle.report(subnet, field="metadata.os")
    protocolReport = censysHandle.report(subnet, field="protocols")
    websrvReport80 = censysHandle.report(subnet, field="80.http.get.headers.server")
    websrvReport8888 = censysHandle.report(subnet, field="8888.http.get.headers.server")
    websrvReport8080 = censysHandle.report(subnet, field="8080.http.get.headers.server")
    poodleVulHost = censysHandle.report(subnet, field="443.https.ssl_3.support")

    for item in osReport["results"]:
        osList.append(item["key"])
        osCount.append(item["doc_count"])

    for item in websrvReport80["results"]:
        websrv80List.append(item["key"])
        websrv80Count.append(item["doc_count"])

    for item in websrvReport8080["results"]:
        websrv8080List.append(item["key"])
        websrv8080Count.append(item["doc_count"])

    for item in websrvReport8888["results"]:
        websrv8888List.append(item["key"])
        websrv8888Count.append(item["doc_count"])

    for item in protocolReport["results"]:
        protocolList.append(item["key"])
        protocolCount.append(item["doc_count"])

    for item in poodleVulHost["results"]:
        poodleHostList.append(item["key_as_string"])
        poodleHostCount.append(item["doc_count"])

    # Plot of Operating systems used vs Host count
    osFigure = graph.Figure(data=[graph.Bar(y=osCount, x=osList, text=osCount, textposition="auto")], layout_title_text="Count of Hosts by Operating "
                                                                                     "System for Subnet " + subnet)
    osFigure.show()

    websrv80Figure = graph.Figure(data=[graph.Bar(y=websrv80Count, x=websrv80List, text=websrv80Count, textposition="auto")], layout_title_text="Count of "
                                                                                                       "Hosts "
                                                                                                       "listening on "
                                                                                                       "Port 80 for "
                                                                                                       "Subnet " +
                                                                                                       subnet)
    websrv80Figure.show()

    websrv8080Figure = graph.Figure(data=[graph.Bar(y=websrv8080Count, x=websrv8080List, text=websrv8080Count, textposition="auto")], layout_title_text="Count "
                                                                                                             "of "
                                                                                                             "Hosts "
                                                                                                             "listening on Port 8080 for Subnet " + subnet)
    websrv8080Figure.show()

    websrv8888Figure = graph.Figure(data=[graph.Bar(y=websrv8888Count, x=websrv8888List, text=websrv8888Count, textposition="auto")], layout_title_text="Count "
                                                                                                             "of "
                                                                                                             "Hosts "
                                                                                                             "listening on Port 8888 for Subnet " + subnet)
    websrv8888Figure.show()

    protocolFigure = graph.Figure(data=[graph.Bar(y=protocolCount, x=protocolList, text=protocolCount, textposition="auto")], layout_title_text="Count of "
                                                                                                       "Hosts by "
                                                                                                       "Protocols for "
                                                                                                       "Subnet " +
                                                                                                       subnet)
    protocolFigure.show()

    poodleHostFigure = graph.Figure(data=[graph.Bar(y=poodleHostCount, x=poodleHostList, text=poodleHostCount, textposition="auto")], layout_title_text="SSLv3 Supported Clients in Subnet " + subnet)
    poodleHostFigure.show()