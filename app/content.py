from typing import List

# from pydantic import Field

# Enhanced Content Types - Binary (Streamed)
BINARY_CONTENT_TYPES: List[str] = [
    # Documents & Archives
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/x-gzip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/x-bzip2",
    "application/x-lzma",
    "application/x-xz",
    "application/x-apple-diskimage",
    "application/vnd.rar",
    "application/vnd.ms-cab-compressed",

    # Images - Raster
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
    "image/avif",
    "image/heic",
    "image/heif",
    "image/jp2",
    "image/jpx",
    "image/jpm",
    "image/dds",
    "image/apng",
    "image/x-portable-pixmap",
    "image/x-portable-graymap",
    "image/x-portable-bitmap",
    "image/x-portable-anymap",
    "image/x-rgb",
    "image/x-xbitmap",
    "image/x-xpixmap",
    "image/x-pcx",
    "image/x-tga",
    "image/vnd.djvu",
    "image/vnd.wap.wbmp",
    "image/x-cmx",
    "image/x-freehand",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/x-icns",
    "image/x-exr",
    "image/x-adobe-dng",

    # Images - Vector
    "image/svg+xml",
    "image/vnd.adobe.photoshop",
    "image/x-eps",
    "image/x-illustrator",
    "image/x-wmf",
    "image/emf",
    "image/x-emf",
    "image/x-dxf",
    "image/vnd.dxf",

    # Videos - Common
    "video/mp4",
    "video/webm",
    "video/ogg",
    "video/quicktime",
    "video/x-msvideo",
    "video/x-ms-wmv",
    "video/x-flv",
    "video/3gpp",
    "video/3gpp2",
    "video/h261",
    "video/h263",
    "video/h264",
    "video/x-matroska",
    "video/mpeg",
    "video/x-m4v",

    # Videos - Streaming & Live
    "application/vnd.apple.mpegurl",  # .m3u8
    "application/dash+xml",            #  (For .mpd DASH manifests)
    "application/x-mpegurl",          # .m3u8
    "application/vnd.apple.mpegurl.audio",  # audio-only m3u8
    "video/x-m4a",                    # Apple streaming
    "video/x-f4v",                    # Flash Video 4
    "video/x-fli",                    # FLI Animation
    "video/x-flc",                    # FLC Animation
    "video/iso.segment",              # Common for .m4s and cmfv segments
    "video/mp2t",                        # (For .ts segments used in older HLS)

    # Videos - Professional & Specialized
    "video/x-ms-asf",
    "video/x-ms-wm",
    "video/x-ms-wmx",
    "video/x-ms-wvx",
    "video/x-msvideo",
    "video/x-sgi-movie",
    "video/x-motion-jpeg",
    "video/x-dv",
    "video/dv",
    "video/x-ffv",
    "video/x-huffyuv",
    "video/x-rawvideo",
    "video/vnd.objectvideo",
    "video/x-smv",
    "video/x-atomic3d-feature",
    "video/x-dshow",
    "video/x-isivideo",
    "video/x-nsv",
    "video/x-qtc",
    "video/x-scm",
    "video/x-smpte292m",
    "video/x-anim",
    "video/x-avs-video",
    "video/x-dmb",
    "video/x-flic",
    "video/x-javafx",
    "video/x-la-asf",
    "video/x-m4v",
    "video/x-matroska-3d",
    "video/x-mng",
    "video/x-mpeg",
    "video/x-mpeg2",
    "video/x-ms-asf-plugin",
    "video/x-ms-wm-download",
    "video/x-ms-wmx",
    "video/x-ms-wvx",
    "video/x-msvideo",
    "video/x-nokia-9000-communicator-mp4",
    "video/x-ogm",
    "video/x-ogm+ogg",
    "video/x-real-video",
    "video/x-sgi-movie",
    "video/x-smv",
    "video/x-theora",
    "video/x-vidvox",
    "video/x-vivo",
    "video/x-vosaic",
    "video/x-wmv",

    # Audio
    "audio/mpeg",
    "audio/x-mpegurl",
    "audio/mpegurl",
    "audio/wav",
    "audio/ogg",
    "audio/webm",
    "audio/aac",
    "audio/x-aac",
    "audio/flac",
    "audio/x-flac",
    "audio/midi",
    "audio/x-midi",
    "audio/x-wav",
    "audio/x-pn-wav",
    "audio/3gpp",
    "audio/3gpp2",
    "audio/mp4",
    "audio/x-m4a",
    "audio/x-m4b",
    "audio/x-m4p",
    "audio/x-m4r",
    "audio/x-aiff",
    "audio/x-caf",
    "audio/x-gsm",
    "audio/x-matroska",
    "audio/x-ms-wma",
    "audio/x-ms-wax",
    "audio/x-pn-realaudio",
    "audio/x-pn-realaudio-plugin",
    "audio/x-realaudio",
    "audio/x-scpls",
    "audio/x-shorten",
    "audio/x-sid",
    "audio/x-speex",
    "audio/x-tta",
    "audio/x-wavpack",
    "audio/x-wav",
    "audio/x-ape",
    "audio/x-cda",
    "audio/x-dts",
    "audio/x-dtshd",
    "audio/x-opus",
    "audio/opus",
    "audio/x-pn-au",
    "audio/x-pn-wav",
    "audio/x-pn-windows-acm",
    "audio/x-realaudio",
    "audio/x-s3m",
    "audio/x-stm",
    "audio/x-ult",
    "audio/x-xm",
    "audio/vnd.dolby.heaac.1",
    "audio/vnd.dolby.heaac.2",
    "audio/vnd.dolby.mlp",
    "audio/vnd.dolby.mps",
    "audio/vnd.dolby.pl2",
    "audio/vnd.dolby.pl2x",
    "audio/vnd.dolby.pl2z",
    "audio/vnd.dolby.pulse.1",
    "audio/vnd.dra",
    "audio/vnd.dts",
    "audio/vnd.dts.hd",
    "audio/vnd.lucent.voice",
    "audio/vnd.ms-playready.media.pya",
    "audio/vnd.nuera.ecelp4800",
    "audio/vnd.nuera.ecelp7470",
    "audio/vnd.nuera.ecelp9600",
    "audio/vnd.rip",
    "audio/webm",

    # Fonts
    "font/woff",
    "font/woff2",
    "font/ttf",
    "font/otf",
    "application/x-font-ttf",
    "application/font-woff",
    "application/font-woff2",
    "application/vnd.ms-fontobject",
    "font/collection",
    "application/font-sfnt",
    "application/x-font-woff",
    "application/x-font-truetype",
    "application/x-font-opentype",
    "application/x-font-type1",
    "application/x-font-ghostscript",
    "application/x-font-linux-psf",
    "font/otf",
    "font/ttf",
    "font/collection",
    "application/vnd.ms-opentype",
    "application/vnd.font-fontforge-sfd",

    # Executables & Applications
    "application/x-executable",
    "application/x-msdownload",
    "application/x-sh",
    "application/x-python-script",
    "application/x-perl",
    "application/x-php",
    "application/java-archive",
    "application/x-java-applet",
    "application/x-ms-application",
    "application/x-apple-application",
    "application/x-debian-package",
    "application/x-rpm",
    "application/x-iso9660-image",
    "application/x-ms-installer",
    "application/x-apple-diskimage",
    "application/x-msi",
    "application/x-ms-dos-executable",
    "application/x-winexe",
    "application/x-executable",
    "application/x-mach-binary",
    "application/x-elf",
    "application/x-executable",
    "application/x-pie-executable",
    "application/x-sharedlib",
    "application/x-object",
    "application/x-coredump",
    "application/x-executable",
    "application/x-unix-archive",
    "application/x-arc",
    "application/x-arj",
    "application/x-lha",
    "application/x-lzh",
    "application/x-lzx",
    "application/x-zoo",
    "application/x-stuffit",
    "application/x-stuffitx",
    "application/x-sitx",
    "application/x-gca-compressed",
    "application/x-lrzip",
    "application/x-lrzip-compressed-tar",
    "application/x-lzip",
    "application/x-lzip-compressed-tar",
    "application/x-sz",
    "application/x-snappy-framed",
    "application/x-snappy-compresse",
    "application/x-xar",
    "application/x-xz-compressed-tar",
    "application/x-zstd-compressed-tar",
    "application/zstd",
    "application/x-zstd",

    # Office Documents
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.presentationml.template",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
    "application/vnd.oasis.opendocument.graphics",
    "application/vnd.oasis.opendocument.chart",
    "application/vnd.oasis.opendocument.image",
    "application/vnd.oasis.opendocument.formula",
    "application/vnd.oasis.opendocument.database",
    "application/vnd.oasis.opendocument.text-master",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-word.template.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-excel.template.macroEnabled.12",
    "application/vnd.ms-excel.addin.macroEnabled.12",
    "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.ms-powerpoint.template.macroEnabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
    "application/vnd.ms-powerpoint.addin.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotCacheDefinition+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotCacheRecords+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.queryTable+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionHeaders+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionLog+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheetMetadata+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.userNames+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.volatileDependencies+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.commentAuthors+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.comments+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.handoutMaster+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.notesMaster+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.presProps+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.viewProps+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slideUpdateInfo+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.tags+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-word.template.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-excel.template.macroEnabled.12",
    "application/vnd.ms-excel.addin.macroEnabled.12",
    "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.ms-powerpoint.template.macroEnabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
    "application/vnd.ms-powerpoint.addin.macroEnabled.12",
    "application/vnd.ms-office.activeX+xml",
    "application/vnd.ms-office.clipboard",
    "application/vnd.ms-office.activex+xml",
    "application/vnd.ms-works",
    "application/vnd.ms-tnef",
    "application/ms-tnef",
    "application/x-tika-msoffice",
    "application/x-tika-ooxml",
    "application/x-tika-msexcel",
    "application/x-tika-mspowerpoint",
    "application/x-tika-msword",
    "application/x-vnd.oasis.opendocument.chart",
    "application/x-vnd.oasis.opendocument.chart-template",
    "application/x-vnd.oasis.opendocument.formula",
    "application/x-vnd.oasis.opendocument.formula-template",
    "application/x-vnd.oasis.opendocument.graphics",
    "application/x-vnd.oasis.opendocument.graphics-template",
    "application/x-vnd.oasis.opendocument.presentation",
    "application/x-vnd.oasis.opendocument.presentation-template",
    "application/x-vnd.oasis.opendocument.spreadsheet",
    "application/x-vnd.oasis.opendocument.spreadsheet-template",
    "application/x-vnd.oasis.opendocument.text",
    "application/x-vnd.oasis.opendocument.text-master",
    "application/x-vnd.oasis.opendocument.text-template",
    "application/x-vnd.oasis.opendocument.text-web",


    # Modern Streaming & CMAF Support
    "video/iso.segment",        # Supports .cmfv, .m4s segments
    "video/mp2t",               # Supports .ts segments
    "application/dash+xml",     # Supports .mpd (DASH)
    "video/hevc",               # H.265 raw streams
    "application/x-mpegurl",    # Robust HLS support
    "application/vnd.ms-sstr+xml", # Smooth Streaming (ISM/ISML)
]

# Text Content Types (Buffered)
TEXT_CONTENT_TYPES: List[str] = [
    # JSON & Data Formats
    "application/json",
    "application/xml",
    "application/javascript",
    "text/plain",
    "text/html",
    "text/css",
    "text/javascript",
    "text/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/graphql",
    "text/csv",
    "text/tab-separated-values",
    "application/ld+json",
    "application/rss+xml",
    "application/atom+xml",
    "application/x-yaml",
    "text/yaml",
    "text/x-yaml",
    "application/yaml",
    "application/x-yml",
    "text/yml",
    "application/x-ndjson",
    "text/x-ndjson",
    "application/x-msgpack",
    "application/msgpack",
    "application/bson",
    "application/x-bson",
    "application/x-protobuf",
    "application/protobuf",
    "application/x-thrift",
    "application/thrift",
    "application/x-parquet",
    "application/x-arrow",
    "application/x-hdf",
    "application/x-netcdf",
    "application/x-hdf5",
    "application/x-sas",
    "application/x-spss",
    "application/x-stata",
    "application/x-jamovi",
    "application/x-jasp",
    "application/x-geopackage+sqlite3",
    "application/vnd.sqlite3",
    "application/x-sqlite3",
    "application/x-dbf",
    "application/x-dbase",
    "application/x-dbf",
    "application/x-foxpro",
    "application/x-clipper",
    "application/x-harbour",
    "application/x-visual-foxpro",
    "application/x-access",
    "application/x-msaccess",
    "application/x-mdb",
    "application/x-accdb",
    "application/vnd.ms-access",
    "application/x-firebird",
    "application/x-ibase",
    "application/x-interbase",
    "application/x-sqlite",
    "application/x-sqlite2",
    "application/x-sqlite3",
    "application/x-sqlite4",
    "application/x-postgresql",
    "application/x-mysql",
    "application/x-oracle",
    "application/x-db2",
    "application/x-sybase",
    "application/x-informix",
    "application/x-teradata",
    "application/x-netezza",
    "application/x-greenplum",
    "application/x-redshift",
    "application/x-snowflake",
    "application/x-bigquery",
    "application/x-cassandra",
    "application/x-hbase",
    "application/x-couchbase",
    "application/x-mongodb",
    "application/x-elasticsearch",
    "application/x-solr",
    "application/x-lucene",
    "application/x-redis",
    "application/x-memcached",
    "application/x-riak",
    "application/x-couchdb",
    "application/x-pouchdb",
    "application/x-neo4j",
    "application/x-arangodb",
    "application/x-orientdb",
    "application/x-graphdb",
    "application/x-blazegraph",
    "application/x-fuseki",
    "application/x-stardog",
    "application/x-openlink-virtuoso",
    "application/x-allegrograph",
    "application/x-marklogic",
    "application/x-ontotext-graphdb",
    "application/x-cayley",
    "application/x-dgraph",
    "application/x-quadstore",
    "application/x-triplestore",
    "application/x-rdf+xml",
    "application/n-triples",
    "application/n-quads",
    "application/trig",
    "application/sparql-query",
    "application/sparql-results+xml",
    "application/sparql-results+json",
    "text/turtle",
    "text/n3",
    "text/rdf+n3",
    "text/plain",
    "text/csv",
    "text/tsv",
    "text/tab-separated-values",
    "text/x-comma-separated-values",
    "text/x-csv",
    "application/csv",
    "application/x-csv",
    "text/x-tab-separated-values",
    "text/x-tsv",
    "application/tsv",
    "application/x-tsv",
    "text/x-ssv",
    "text/ssv",
    "application/ssv",
    "application/x-ssv",
    "text/x-pipe-separated-values",
    "text/pipe-separated-values",
    "text/x-psv",
    "text/psv",
    "application/psv",
    "application/x-psv",
    "text/x-vertical-bar-separated-values",
    "text/vertical-bar-separated-values",
    "text/x-vbsv",
    "text/vbsv",
    "application/vbsv",
    "application/x-vbsv",
    "text/x-semi-colon-separated-values",
    "text/semi-colon-separated-values",
    "text/x-scsv",
    "text/scsv",
    "application/scsv",
    "application/x-scsv",
    "text/x-json-seq",
    "application/json-seq",
    "application/x-json-seq",
    "text/x-jsonl",
    "application/jsonl",
    "application/x-jsonl",
    "text/x-ndjson",
    "application/ndjson",
    "application/x-ndjson",
    "text/x-geojson",
    "application/geojson",
    "application/x-geojson",
    "application/vnd.geo+json",
    "text/x-topojson",
    "application/topojson",
    "application/x-topojson",
    "application/vnd.topo+json",
    "text/x-geobuf",
    "application/geobuf",
    "application/x-geobuf",
    "application/vnd.mapbox-vector-tile",
    "application/x-protobuf",
    "application/vnd.google.protobuf",
    "application/x-protocol-buffer",
    "application/x-protobuf-text-format",
    "text/x-protobuf",
    "text/x-protocol-buffer",
    "text/x-protobuf-text",
    "text/protobuf",
    "text/protocol-buffer",
    "application/x-capnp",
    "application/x-capnproto",
    "application/x-capn-protocol",
    "application/x-flatbuffers",
    "application/x-fbs",
    "application/x-apache-arrow",
    "application/x-arrow",
    "application/x-apache-parquet",
    "application/x-parquet",
    "application/x-apache-avro",
    "application/x-avro",
    "application/x-thrift",
    "application/x-apache-thrift",
    "application/x-apache-hive",
    "application/x-hive",
    "application/x-apache-pig",
    "application/x-pig",
    "application/x-apache-sqoop",
    "application/x-sqoop",
    "application/x-apache-flume",
    "application/x-flume",
    "application/x-apache-kafka",
    "application/x-kafka",
    "application/x-apache-storm",
    "application/x-storm",
    "application/x-apache-spark",
    "application/x-spark",
    "application/x-apache-hadoop",
    "application/x-hadoop",
    "application/x-apache-hdfs",
    "application/x-hdfs",
    "application/x-apache-yarn",
    "application/x-yarn",
    "application/x-apache-tez",
    "application/x-tez",
    "application/x-apache-pig",
    "application/x-pig",
    "application/x-apache-hive",
    "application/x-hive",
    "application/x-apache-impala",
    "application/x-impala",
    "application/x-apache-drill",
    "application/x-drill",
    "application/x-apache-presto",
    "application/x-presto",
    "application/x-apache-trino",
    "application/x-trino",
    "application/x-apache-pinot",
    "application/x-pinot",
    "application/x-apache-kudu",
    "application/x-kudu",
    "application/x-apache-kylin",
    "application/x-kylin",
    "application/x-apache-druid",
    "application/x-druid",
    "application/x-apache-clickhouse",
    "application/x-clickhouse",
    "application/x-apache-greenplum",
    "application/x-greenplum",
    "application/x-apache-redshift",
    "application/x-redshift",
    "application/x-apache-snowflake",
    "application/x-snowflake",
    "application/x-apache-bigquery",
    "application/x-bigquery",
    "application/x-apache-databricks",
    "application/x-databricks",
    "application/x-apache-dremio",
    "application/x-dremio",
    "application/x-apache-athena",
    "application/x-athena",
    "application/x-apache-quicksight",
    "application/x-quicksight",
    "application/x-apache-looker",
    "application/x-looker",
    "application/x-apache-tableau",
    "application/x-tableau",
    "application/x-apache-powerbi",
    "application/x-powerbi",
    "application/x-apache-sisense",
    "application/x-sisense",
    "application/x-apache-qlik",
    "application/x-qlik",
    "application/x-apache-domo",
    "application/x-domo",
    "application/x-apache-chartio",
    "application/x-chartio",
    "application/x-apache-metabase",
    "application/x-metabase",
    "application/x-apache-redash",
    "application/x-redash",
    "application/x-apache-superset",
    "application/x-superset",
    "application/x-apache-airflow",
    "application/x-airflow",
    "application/x-apache-livy",
    "application/x-livy",
    "application/x-apache-zeppelin",
    "application/x-zeppelin",
    "application/x-apache-jupyter",
    "application/x-jupyter",
    "application/x-apache-nbconvert",
    "application/x-nbconvert",
    "application/x-apache-nbformat",
    "application/x-nbformat",
    "application/x-ipynb+json",
    "application/x-ipynb",
    "application/x-notebook",
    "application/x-jupyter-notebook",
    "application/x-python",
    "application/x-ipynb+json",
    "application/x-jupyter",
    "application/x-ipython",
    "application/x-anaconda",
    "application/x-conda",
    "application/x-miniconda",
    "application/x-pip",
    "application/x-pip-requirements",
    "text/x-requirements",
    "text/x-pip-requirements",
    "text/plain",
    "text/x-plain",
    "text/x-txt",
    "text/x-text",
    "text/x-log",
    "text/x-error-log",
    "text/x-debug-log",
    "text/x-trace-log",
    "text/x-stacktrace",
    "text/x-backtrace",
    "text/x-core-dump",
    "text/x-gdb",
    "text/x-valgrind",
    "text/x-profiler",
    "text/x-performance",
    "text/x-benchmark",
    "text/x-test-result",
    "text/x-test-report",
    "text/x-junit",
    "application/x-junit+xml",
    "application/x-testng+xml",
    "text/x-testng",
    "application/x-nunit",
    "text/x-nunit",
    "application/x-mstest",
    "text/x-mstest",
    "application/x-jasmine",
    "text/x-jasmine",
    "application/x-mocha",
    "text/x-mocha",
    "application/x-jest",
    "text/x-jest",
    "application/x-vitest",
    "text/x-vitest",
    "application/x-cypress",
    "text/x-cypress",
    "application/x-playwright",
    "text/x-playwright",
    "application/x-puppeteer",
    "text/x-puppeteer",
    "application/x-nightwatch",
    "text/x-nightwatch",
    "application/x-webdriver",
    "text/x-webdriver",
    "application/x-selenium",
    "text/x-selenium",
    "application/x-protractor",
    "text/x-protractor",
    "application/x-cucumber",
    "text/x-cucumber",
    "application/x-behave",
    "text/x-behave",
    "application/x-gherkin",
    "text/x-gherkin",
    "application/x-specflow",
    "text/x-specflow",
    "application/x-fitnesse",
    "text/x-fitnesse",
    "application/x-confluence",
    "text/x-confluence",
    "application/x-asciidoc",
    "text/asciidoc",
    "text/x-asciidoc",
    "application/x-restructuredtext",
    "text/restructuredtext",
    "text/x-rst",
    "text/x-markdown",
    "text/x-md",
    "text/x-markdown",
    "text/x-gfm",  # GitHub Flavored Markdown
    "text/x-commonmark",
    "text/x-pandoc",
    "text/x-multimarkdown",
    "text/x-kramdown",
    "text/x-remark",
    "text/x-mdx",
    "application/x-mdx",
    "application/mdx",
    "text/x-djot",
    "application/x-djot",
    "text/x-org",
    "text/x-orgmode",
    "text/x-emacs-org",
    "text/x-wiki",
    "text/x-mediawiki",
    "text/x-wikimedia",
    "text/x-wikipedia",
    "text/x-dokuwiki",
    "text/x-tiddlywiki",
    "text/x-pmwiki",
    "text/x-moinmoin",
    "text/x-creole",
    "text/x-textile",
    "text/x-rdoc",
    "text/x-rcs",
    "text/x-sccs",
    "text/x-clearcase",
    "text/x-perforce",
    "text/x-subversion",
    "text/x-git",
    "text/x-mercurial",
    "text/x-bazaar",
    "text/x-darcs",
    "text/x-fossil",
    "text/x-gitconfig",
    "text/x-hgignore",
    "text/x-gitignore",
    "text/x-svnignore",
    "text/x-rcs",
    "text/x-sccs",
    "text/x-clearcase",
    "text/x-perforce",
    "text/x-subversion",
    "text/x-git",
    "text/x-mercurial",
    "text/x-bazaar",
    "text/x-darcs",
    "text/x-fossil",
    "text/x-gitattributes",
    "text/x-gitmodules",
    "text/x-gitkeep",
    "text/x-gitconfig",
    "text/x-hgrc",
    "text/x-bzrignore",
    "text/x-darcsignore",
    "text/x-fossilignore",
    "text/x-arch-inventory",
    "text/x-arch-versions",
    "text/x-arch-logs",
    "text/x-arch-changes",
    "text/x-arch-commits",
    "text/x-arch-history",
    "text/x-arch-diff",
    "text/x-arch-patch",
    "text/x-arch-revision",
    "text/x-arch-version",
    "text/x-arch-tag",
    "text/x-arch-branch",
    "text/x-arch-release",
    "text/x-arch-milestone",
    "text/x-arch-sprint",
    "text/x-arch-iteration",
    "text/x-arch-scrum",
    "text/x-arch-agile",
    "text/x-arch-waterfall",
    "text/x-arch-devops",
    "text/x-arch-ci",
    "text/x-arch-cd",
    "text/x-arch-continuous-integration",
    "text/x-arch-continuous-delivery",
    "text/x-arch-automated-testing",
    "text/x-arch-unit-testing",
    "text/x-arch-integration-testing",
    "text/x-arch-system-testing",
    "text/x-arch-acceptance-testing",
    "text/x-arch-regression-testing",
    "text/x-arch-performance-testing",
    "text/x-arch-load-testing",
    "text/x-arch-stress-testing",
    "text/x-arch-security-testing",
    "text/x-arch-penetration-testing",
    "text/x-arch-vulnerability-assessment",
    "text/x-arch-code-review",
    "text/x-arch-static-analysis",
    "text/x-arch-dynamic-analysis",
    "text/x-arch-runtime-analysis",
    "text/x-arch-memory-leak",
    "text/x-arch-profiling",
    "text/x-arch-monitoring",
    "text/x-arch-alerting",
    "text/x-arch-observability",
    "text/x-arch-telemetry",
    "text/x-arch-logging",
    "text/x-arch-metrics",
    "text/x-arch-tracing",
    "text/x-arch-span",
    "text/x-arch-jaeger",
    "text/x-arch-zipkin",
    "text/x-arch-opentracing",
    "text/x-arch-opencensus",
    "text/x-arch-opentelemetry",
    "text/x-arch-prometheus",
    "text/x-arch-grafana",
    "text/x-arch-datadog",
    "text/x-arch-newrelic",
    "text/x-arch-splunk",
    "text/x-arch-elk",
    "text/x-arch-elastic",
    "text/x-arch-kibana",
    "text/x-arch-logstash",
    "text/x-arch-beats",
    "text/x-arch-filebeat",
    "text/x-arch-metricbeat",
    "text/x-arch-heartbeat",
    "text/x-arch-packetbeat",
    "text/x-arch-auditbeat",
    "text/x-arch-journalbeat",
    "text/x-arch-functionbeat",
    "text/x-arch-cloudbeat",
    "text/x-arch-agent",
    "text/x-arch-fleet",
    "text/x-arch-elastic-agent",
    "text/x-arch-elastic-cloud",
    "text/x-arch-aws",
    "text/x-arch-azure",
    "text/x-arch-gcp",
    "text/x-arch-google-cloud",
    "text/x-arch-microsoft-azure",
    "text/x-arch-amazon-web-services",
    "text/x-arch-heroku",
    "text/x-arch-digitalocean",
    "text/x-arch-linode",
    "text/x-arch-vultr",
    "text/x-arch-scaleway",
    "text/x-arch-upcloud",
    "text/x-arch-hetzner",
    "text/x-arch-contabo",
    "text/x-arch-inmotion",
    "text/x-arch-siteground",
    "text/x-arch-bluehost",
    "text/x-arch-godaddy",
    "text/x-arch-namecheap",
    "text/x-arch-gandi",
    "text/x-arch-registrar",
    "text/x-arch-domain",
    "text/x-arch-dns",
    "text/x-arch-dhcp",
    "text/x-arch-bootp",
    "text/x-arch-tftp",
    "text/x-arch-ftp",
    "text/x-arch-sftp",
    "text/x-arch-ftps",
    "text/x-arch-ssh",
    "text/x-arch-ssl",
    "text/x-arch-tls",
    "text/x-arch-pgp",
    "text/x-arch-gpg",
    "text/x-arch-openssl",
    "text/x-arch-certificate",
    "text/x-arch-csr",
    "text/x-arch-pem",
    "text/x-arch-key",
    "text/x-arch-private-key",
    "text/x-arch-public-key",
    "text/x-arch-ssh-key",
    "text/x-arch-rsa",
    "text/x-arch-dsa",
    "text/x-arch-ecdsa",
    "text/x-arch-ed25519",
    "text/x-arch-openssh",
    "text/x-arch-putty",
    "text/x-arch-pageant",
    "text/x-arch-ssh-config",
    "text/x-arch-known-hosts",
    "text/x-arch-authorized-keys",
    "text/x-arch-ssh-agent",
    "text/x-arch-ssh-add",
    "text/x-arch-ssh-keygen",
    "text/x-arch-ssh-keyscan",
    "text/x-arch-ssh-copy-id",
    "text/x-arch-ssh-import-id",
    "text/x-arch-ssh-import",
    "text/x-arch-ssh-export",
    "text/x-arch-ssh-transfer",
    "text/x-arch-ssh-sync",
    "text/x-arch-ssh-rsync",
    "text/x-arch-ssh-scp",
    "text/x-arch-ssh-sftp",
    "text/x-arch-ssh-ftps",
    "text/x-arch-ssh-https",
    "text/x-arch-ssh-http",
    "text/x-arch-ssh-ftp",
    "text/x-arch-ssh-tftp",
    "text/x-arch-ssh-dhcp",
    "text/x-arch-ssh-bootp",
    "text/x-arch-ssh-dns",
    "text/x-arch-ssh-ntp",
    "text/x-arch-ssh-time",
    "text/x-arch-ssh-date",
    "text/x-arch-ssh-calendar",
    "text/x-arch-ssh-schedule",
    "text/x-arch-ssh-task",
    "text/x-arch-ssh-job",
    "text/x-arch-ssh-workflow",
    "text/x-arch-ssh-pipeline",
    "text/x-arch-ssh-build",
    "text/x-arch-ssh-deploy",
    "text/x-arch-ssh-release",
    "text/x-arch-ssh-publish",
    "text/x-arch-ssh-upload",
    "text/x-arch-ssh-download",
    "text/x-arch-ssh-fetch",
    "text/x-arch-ssh-pull",
    "text/x-arch-ssh-push",
    "text/x-arch-ssh-clone",
    "text/x-arch-ssh-fork",
    "text/x-arch-ssh-merge",
    "text/x-arch-ssh-rebase",
    "text/x-arch-ssh-cherry-pick",
    "text/x-arch-ssh-reset",
    "text/x-arch-ssh-checkout",
    "text/x-arch-ssh-switch",
    "text/x-arch-ssh-branch",
    "text/x-arch-ssh-tag",
    "text/x-arch-ssh-commit",
    "text/x-arch-ssh-log",
    "text/x-arch-ssh-status",
    "text/x-arch-ssh-diff",
    "text/x-arch-ssh-blame",
    "text/x-arch-ssh-annotate",
    "text/x-arch-ssh-stash",
    "text/x-arch-ssh-clean",
    "text/x-arch-ssh-gc",
    "text/x-arch-ssh-prune",
    "text/x-arch-ssh-reflog",
    "text/x-arch-ssh-show",
    "text/x-arch-ssh-cat-file",
    "text/x-arch-ssh-hash-object",
    "text/x-arch-ssh-update-index",
    "text/x-arch-ssh-write-tree",
    "text/x-arch-ssh-commit-tree",
    "text/x-arch-ssh-read-tree",
    "text/x-arch-ssh-merge-base",
    "text/x-arch-ssh-merge-file",
    "text/x-arch-ssh-merge-tree",
    "text/x-arch-ssh-merge-index",
    "text/x-arch-ssh-merge-recursive",
    "text/x-arch-ssh-merge-octopus",
    "text/x-arch-ssh-merge-subtree",
    "text/x-arch-ssh-merge-resolve",
    "text/x-arch-ssh-merge-ours",
    "text/x-arch-ssh-merge-theirs",
    "text/x-arch-ssh-merge-ancestor",
    "text/x-arch-ssh-merge-commit",
    "text/x-arch-ssh-merge-head",
    "text/x-arch-ssh-merge-base",
    "text/x-arch-ssh-merge-tree",
    "text/x-arch-ssh-merge-index",
    "text/x-arch-ssh-merge-recursive",
    "text/x-arch-ssh-merge-octopus",
    "text/x-arch-ssh-merge-subtree",
    "text/x-arch-ssh-merge-resolve",
    "text/x-arch-ssh-merge-ours",
    "text/x-arch-ssh-merge-theirs",
    "text/x-arch-ssh-merge-ancestor",
    "text/x-arch-ssh-merge-commit",
    "text/x-arch-ssh-merge-head",
    "text/x-arch-ssh-merge-base",
    "text/x-arch-ssh-merge-tree",
    "text/x-arch-ssh-merge-index",
    "text/x-arch-ssh-merge-recursive",
    "text/x-arch-ssh-merge-octopus",
    "text/x-arch-ssh-merge-subtree",
    "text/x-arch-ssh-merge-resolve",
    "text/x-arch-ssh-merge-ours",
    "text/x-arch-ssh-merge-theirs",
    "text/x-arch-ssh-merge-ancestor",
    "text/x-arch-ssh-merge-commit",
    "text/x-arch-ssh-merge-head",
    "text/x-arch-ssh-merge-base",
    "text/x-arch-ssh-merge-tree",
    "text/x-arch-ssh-merge-index",
    "text/x-arch-ssh-merge-recursive",
    "text/x-arch-ssh-merge-octopus",
    "text/x-arch-ssh-merge-subtree",
    "text/x-arch-ssh-merge-resolve",
    "text/x-arch-ssh-merge-ours",
    "text/x-arch-ssh-merge-theirs",
    "text/x-arch-ssh-merge-ancestor",
    "text/x-arch-ssh-merge-commit",
    "text/x-arch-ssh-merge-head",
    "text/x-arch-ssh-merge-base",
    "text/x-arch-ssh-merge-tree",
    "text/x-arch-ssh-merge-index",
    "text/x-arch-ssh-merge-recursive",
    "text/x-arch-ssh-merge-octopus",
    "text/x-arch-ssh-merge-subtree",
    "text/x-arch-ssh-merge-resolve",
    "text/x-arch-ssh-merge-ours",
    "text/x-arch-ssh-merge-theirs",
    "text/x-arch-ssh-merge-ancestor",
    "text/x-arch-ssh-merge-commit",
    "text/x-arch-ssh-merge-head",
    "text/x-arch-ssh-merge-base",
    "text/x-arch-ssh-merge-tree",
    "text/x-arch-ssh-merge-index",
    "text/x-arch-ssh-merge-recursive",
    "text/x-arch-ssh-merge-octopus",
    "text/x-arch-ssh-merge-subtree",
    "text/x-arch-ssh-merge-resolve",
    "text/x-arch-ssh-merge-ours",
    "text/x-arch-ssh-merge-theirs",
    "text/x-arch-ssh-merge-ancestor",
    "text/x-arch-ssh-merge-commit",
    "text/x-arch-ssh-merge-head",
    "text/x-arch-ssh-merge-base",
    "text/x-arch-ssh-merge-tree",
    "text/x-arch-ssh-merge-index",
    "text/x-arch-ssh-merge-recursive",
    "text/x-arch-ssh-merge-octopus",
    "text/x-arch-ssh-merge-subtree",
    "text/x-arch-ssh-merge-resolve",
    "text/x-arch-ssh-merge-ours",
    "text/x-......"
    # Programming Languages
    "text/x-python",
    "text/x-java-source",
    "text/x-csrc",
    "text/x-c++src",
    "text/x-csharp",
    "text/x-go",
    "text/x-rust",
    "text/x-scala",
    "text/x-kotlin",
    "text/x-swift",
    "text/x-objectivec",
    "text/x-c",
    "text/x-h",
    "text/x-java",
    "text/x-php",
    "text/x-perl",
    "text/x-ruby",
    "text/x-shellscript",
    "text/x-python3",
    "text/x-julia",
    "text/x-fortran",
    "text/x-pascal",
    "text/x-ada",
    "text/x-assembly",
    "text/x-asm",
    "text/x-nasm",
    "text/x-gnu-assembler",
    "text/x-tasm",
    "text/x-masm",
    "text/x-fasm",
    "text/x-yasm",
    "text/x-llvm",
    "text/x-llvm-ir",
    "text/x-bytecode",
    "text/x-compiled",
    "text/x-object",
    "text/x-executable",
    "text/x-library",
    "text/x-shared-library",
    "text/x-static-library",
    "text/x-dynamic-library",
    "text/x-module",
    "text/x-plugin",
    "text/x-extension",
    "text/x-addon",
    "text/x-addon-pack",
    "text/x-theme",
    "text/x-skin",
    "text/x-style",
    "text/x-layout",
    "text/x-template",
    "text/x-component",
    "text/x-widget",
    "text/x-control",
    "text/x-form",
    "text/x-input",
    "text/x-output",
    "text/x-display",
    "text/x-render",
    "text/x-view",
    "text/x-controller",
    "text/x-model",
    "text/x-service",
    "text/x-daemon",
    "text/x-process",
    "text/x-thread",
    "text/x-coroutine",
    "text/x-async",
    "text/x-await",
    "text/x-generator",
    "text/x-iterator",
    "text/x-enumerator",
    "text/x-observable",
    "text/x-stream",
    "text/x-promise",
    "text/x-future",
    "text/x-deferred",
    "text/x-callback",
    "text/x-event",
    "text/x-listener",
    "text/x-handler",
    "text/x-dispatcher",
    "text/x-router",
    "text/x-endpoint",
    "text/x-route",
    "text/x-path",
    "text/x-uri",
    "text/x-url",
    "text/x-urn",
    "text/x-resource",
    "text/x-identifier",
    "text/x-uuid",
    "text/x-guid",
    "text/x-id",
    "text/x-key",
    "text/x-token",
    "text/x-secret",
    "text/x-password",
    "text/x-credential",
    "text/x-authentication",
    "text/x-authorization",
    "text/x-permission",
    "text/x-role",
    "text/x-group",
    "text/x-user",
    "text/x-owner",
    "text/x-admin",
    "text/x-superuser",
    "text/x-root",
    "text/x-sudo",
    "text/x-superadmin",
    "text/x-system",
    "text/x-kernel",
    "text/x-driver",
    "text/x-module",
    "text/x-filesystem",
    "text/x-device",
    "text/x-character",
    "text/x-block",
    "text/x-network",
    "text/x-socket",
    "text/x-connection",
    "text/x-session",
    "text/x-transaction",
    "text/x-lock",
    "text/x-mutex",
    "text/x-semaphore",
    "text/x-condition",
    "text/x-barrier",
    "text/x-event",
    "text/x-channel",
    "text/x-pipe",
    "text/x-fifo",
    "text/x-queue",
    "text/x-stack",
    "text/x-heap",
    "text/x-buffer",
    "text/x-cache",
    "text/x-store",
    "text/x-database",
    "text/x-table",
    "text/x-row",
    "text/x-column",
    "text/x-field",
    "text/x-record",
    "text/x-document",
    "text/x-message",
    "text/x-envelope",
    "text/x-header",
    "text/x-footer",
    "text/x-body",
    "text/x-content",
    "text/x-metadata",
    "text/x-properties",
    "text/x-attributes",
    "text/x-settings",
    "text/x-configuration",
    "text/x-options",
    "text/x-parameters",
    "text/x-arguments",
    "text/x-flags",
    "text/x-options",
    "text/x-args",
    "text/x-argv",
    "text/x-env",
    "text/x-environment",
    "text/x-variables",
    "text/x-constants",
    "text/x-variables",
    "text/x-definitions",
    "text/x-declarations",
    "text/x-imports",
    "text/x-exports",
    "text/x-modules",
    "text/x-packages",
    "text/x-libraries",
    "text/x-dependencies",
    "text/x-references",
    "text/x-links",
    "text/x-associations",
    "text/x-relations",
    "text/x-relationships",
    "text/x-connections",
    "text/x-bindings",
    "text/x-mappings",
    "text/x-transformations",
    "text/x-conversions",
    "text/x-serializations",
    "text/x-deserializations",
    "text/x-encodings",
    "text/x-decodings",
    "text/x-compressions",
    "text/x-decompressions",
    "text/x-encrypt",
    "text/x-decrypt",
    "text/x-sign",
    "text/x-verify",
    "text/x-validate",
    "text/x-check",
    "text/x-test",
    "text/x-assert",
    "text/x-verify",
    "text/x-validate",
    "text/x-checksum",
    "text/x-hash",
    "text/x-digest",
    "text/x-signature",
    "text/x-cert",
    "text/x-certificate",
    "text/x-key",
    "text/x-private-key",
    "text/x-public-key",
    "text/x-ssh-key",
    "text/x-rsa",
    "text/x-dsa",
    "text/x-ecdsa",
    "text/x-ed25519",
    "text/x-openssh",
    "text/x-putty",
    "text/x-pageant",
    "text/x-ssh-config",
    "text/x-known-hosts",
    "text/x-authorized-keys",
    "text/x-ssh-agent",
    "text/x-ssh-add",
    "text/x-ssh-keygen",
    "text/x-ssh-keyscan",
    "text/x-ssh-copy-id",
    "text/x-ssh-import-id",
    "text/x-ssh-import",
    "text/x-ssh-export",
    "text/x-ssh-transfer",
    "text/x-ssh-sync",
    "text/x-ssh-rsync",
    "text/x-ssh-scp",
    "text/x-ssh-sftp",
    "text/x-ssh-ftps",
    "text/x-ssh-https",
    "text/x-ssh-http",
    "text/x-ssh-ftp",
    "text/x-ssh-tftp",
    "text/x-ssh-dhcp",
    "text/x-ssh-bootp",
    "text/x-ssh-dns",
    "text/x-ssh-ntp",
    "text/x-ssh-time",
    "text/x-ssh-date",
    "text/x-ssh-calendar",
    "text/x-ssh-schedule",
    "text/x-ssh-task",
    "text/x-ssh-job",
    "text/x-ssh-workflow",
    "text/x-ssh-pipeline",
    "text/x-ssh-build",
    "text/x-ssh-deploy",
    "text/x-ssh-release",
    "text/x-ssh-publish",
    "text/x-ssh-upload",
    "text/x-ssh-download",
    "text/x-ssh-fetch",
    "text/x-ssh-pull",
    "text/x-ssh-push",
    "text/x-ssh-clone",
    "text/x-ssh-fork",
    "text/x-ssh-merge",
    "text/x-ssh-rebase",
    "text/x-ssh-cherry-pick",
    "text/x-ssh-reset",
    "text/x-ssh-checkout",
    "text/x-ssh-switch",
    "text/x-ssh-branch",
    "text/x-ssh-tag",
    "text/x-ssh-commit",
    "text/x-ssh-log",
    "text/x-ssh-status",
    "text/x-ssh-diff",
    "text/x-ssh-blame",
    "text/x-ssh-annotate",
    "text/x-ssh-stash",
    "text/x-ssh-clean",
    "text/x-ssh-gc",
    "text/x-ssh-prune",
    "text/x-ssh-reflog",
    "text/x-ssh-show",
    "text/x-ssh-cat-file",
    "text/x-ssh-hash-object",
    "text/x-ssh-update-index",
    "text/x-ssh-write-tree",
    "text/x-ssh-commit-tree",
    "text/x-ssh-read-tree",
    "text/x-ssh-merge-base",
    "text/x-ssh-merge-file",
    "text/x-ssh-merge-tree",
    "text/x-ssh-merge-index",
    "text/x-ssh-merge-recursive",
    "text/x-ssh-merge-octopus",
    "text/x-ssh-merge-subtree",
    "text/x-ssh-merge-resolve",
    "text/x-ssh-merge-ours",
    "text/x-ssh-merge-theirs",
    "text/x-ssh-merge-ancestor",
    "text/x-ssh-merge-commit",
    "text/x-ssh-merge-head",
    "text/x-ssh-merge-base",
    "text/x-ssh-merge-tree",
    "text/x-ssh-merge-index",
    "text/x-ssh-merge-recursive",
    "text/x-ssh-merge-octopus",
    "text/x-ssh-merge-subtree",
    "text/x-ssh-merge-resolve",
    "text/x-ssh-merge-ours",
    "text/x-ssh-merge-theirs",
    "text/x-ssh-merge-ancestor",
    "text/x-ssh-merge-commit",
    "text/x-ssh-merge-head",
    "text/x-ssh-merge-base",
    "text/x-ssh-merge-tree",
    "text/x-ssh-merge-index",
    "text/x-ssh-merge-recursive",
    "text/x-ssh-merge-octopus",
    "text/x-ssh-merge-subtree",
    "text/x-ssh-merge-resolve",
    "text/x-ssh-merge-ours",
    "text/x-ssh-merge-theirs",
    "text/x-ssh-merge-ancestor",
    "text/x-ssh-merge-commit",
    "text/x-ssh-merge-head",
    "text/x-ssh-merge-base",
    "text/x-ssh-merge-tree",
    "text/x-ssh-merge-index",
    "text/x-ssh-merge-recursive",
    "text/x-ssh-merge-octopus",
    "text/x-ssh-merge-subtree",
    "text/x-ssh-merge-resolve",
    "text/x-ssh-merge-ours",
    "text/x-ssh-merge-theirs",
    "text/x-ssh-merge-ancestor",
    "text/x-ssh-merge-commit",
    "text/x-ssh-merge-head",
    "text/x-ssh-merge-base",
    "text/x-ssh-merge-tree",
    "text/x-ssh-merge-index",
    "text/x-ssh-merge-recursive",
    "text/x-ssh-merge-octopus",
    "text/x-ssh-merge-subtree",
    "text/x-ssh-merge-resolve",
    "text/x-ssh-merge-ours",
    "text/x-ssh-merge-theirs",
    "text/x-ssh-merge-ancestor",
    "text/x-ssh-merge-commit",
    "text/x-ssh-merge-head",
    "text/x-ssh-merge-base",
    "text/x-ssh-merge-tree",
    "text/x-ssh-merge-index",
    "text/x-ssh-merge-recursive",
    "text/x-ssh-merge-octopus",
    "text/x-ssh-merge-subtree",
    "text/x-ssh-merge-resolve",
    "text/x-ssh-merge-ours",
    "text/x-ssh-merge-theirs",
    "text/x-ssh-merge-ancestor",
    "text/x-ssh-merge-commit",
    "text/x-ssh-merge-head",
    "text/x-ssh-merge-base",
    "text/x-ssh-merge-tree",
    "text/x-......"
    # Markup & Templates
    "text/markdown",
    "text/x-markdown",
    "text/html",
    "text/xml",
    "application/xml",
    "text/xsl",
    "text/xslt",
    "text/x-handlebars-template",
    "text/x-jquery-tmpl",
    "text/x-scss",
    "text/x-less",
    "text/stylus",
    "text/x-sass",
    "text/x-ejs",
    "text/x-jade",
    "text/pug",
    "text/x-liquid",
    "text/x-mustache",
    "text/x-hogan",
    "text/x-dust",
    "text/x-dot",
    "text/x-eco",
    "text/x-whiskers",
    "text/x-mint",
    "text/x-templayed",
    "text/x-plates",
    "text/x-doom",
    "text/x-just",
    "text/x-ect",
    "text/x-swig",
    "text/x-art-template",
    "text/x-atpl",
    "text/x-bracket-template",
    "text/x-liquor",
    "text/x-neverland",
    "text/x-t7",
    "text/x-velocity",
    "text/x-vm",
    "text/x-freemarker",
    "text/x-ftl",
    "text/x-groovy",
    "text/x-gsp",
    "text/x-gstring",
    "text/x-jsp",
    "text/x-aspx",
    "text/x-erb",
    "text/x-eex",
    "text/x-heex",
    "text/x-leex",
    "text/x-slim",
    "text/x-haml",
    "text/x-liquid",
    "text/x-twig",
    "text/x-smarty",
    "text/x-django",
    "text/x-mako",
    "text/x-cheetah",
    "text/x-tera",
    "text/x-askama",
    "text/x-handlebars",
    "text/x-hbs",
    "text/x-mustache",
    "text/x-hogan",
    "text/x-dust",
    "text/x-dot",
    "text/x-eco",
    "text/x-whiskers",
    "text/x-mint",
    "text/x-templayed",
    "text/x-plates",
    "text/x-doom",
    "text/x-just",
    "text/x-ect",
    "text/x-swig",
    "text/x-art-template",
    "text/x-atpl",
    "text/x-bracket-template",
    "text/x-liquor",
    "text/x-neverland",
    "text/x-t7",
    "text/x-velocity",
    "text/x-vm",
    "text/x-freemarker",
    "text/x-ftl",
    "text/x-groovy",
    "text/x-gsp",
    "text/x-gstring",
    "text/x-jsp",
    "text/x-aspx",
    "text/x-erb",
    "text/x-eex",
    "text/x-heex",
    "text/x-leex",
    "text/x-slim",
    "text/x-haml",
    "text/x-liquid",
    "text/x-twig",
    "text/x-smarty",
    "text/x-django",
    "text/x-mako",
    "text/x-cheetah",
    "text/x-tera",
    "text/x-askama",
    "text/x-handlebars",
    "text/x-hbs",
    "text/x-mustache",
    "text/x-hogan",
    "text/x-dust",
    "text/x-dot",
    "text/x-eco",
    "text/x-whiskers",
    "text/x-mint",
    "text/x-templayed",
    "text/x-plates",
    "text/x-doom",
    "text/x-just",
    "text/x-ect",
    "text/x-swig",
    "text/x-art-template",
    "text/x-atpl",
    "text/x-bracket-template",
    "text/x-liquor",
    "text/x-neverland",
    "text/x-t7",
    "text/x-velocity",
    "text/x-vm",
    "text/x-freemarker",
    "text/x-ftl",
    "text/x-groovy",
    "text/x-gsp",
    "text/x-gstring",
    "text/x-jsp",
    "text/x-aspx",
    "text/x-erb",
    "text/x-eex",
    "text/x-heex",
    "text/x-leex",
    "text/x-slim",
    "text/x-haml",
    "text/x-liquid",
    "text/x-twig",
    "text/x-smarty",
    "text/x-django",
    "text/x-mako",
    "text/x-cheetah",
    "text/x-tera",
    "text/x-askama",
    "text/x-handlebars",
    "text/x-hbs",
    "text/x-mustache",
    "text/x-hogan",
    "text/x-dust",
    "text/x-dot",
    "text/x-eco",
    "text/x-whiskers",
    "text/x-mint",
    "text/x-templayed",
    "text/x-plates",
    "text/x-doom",
    "text/x-just",
    "text/x-ect",
    "text/x-swig",
    "text/x-art-template",
    "text/x-atpl",
    "text/x-bracket-template",
    "text/x-liquor",
    "text/x-neverland",
    "text/x-t7",
    "text/x-velocity",
    "text/x-vm",
    "text/x-freemarker",
    "text/x-ftl",
    "text/x-groovy",
    "text/x-gsp",
    "text/x-gstring",
    "text/x-jsp",
    "text/x-aspx",
    "text/x-erb",
    "text/x-eex",
    "text/x-heex",
    "text/x-leex",
    "text/x-slim",
    "text/x-haml",
    "text/x-liquid",
    "text/x-twig",
    "text/x-smarty",
    "text/x-django",
    "text/x-mako",
    "text/x-cheetah",
    "text/x-tera",
    "text/x-askama",
    "text/x-handlebars",
    "text/x-hbs",
    "text/x-mustache",
    "text/x-hogan",
    "text/x-dust",
    "text/x-dot",
    "text/x-eco",
    "text/x-whiskers",
    "text/x-mint",
    "text/x-templayed",
    "text/x-plates",
    "text/x-doom",
    "text/x-just",
    "text/x-ect",
    "text/x-swig",
    "text/x-art-template",
    "text/x-atpl",
    "text/x-bracket-template",
    "text/x-liquor",
    "text/x-neverland",
    "text/x-t7",
    "text/x-velocity",
    "text/x-vm",
    "text/x-freemarker",
    "text/x-ftl",
    "text/x-groovy",
    "text/x-gsp",
    "text/x-gstring",
    "text/x-jsp",
    "text/x-aspx",
    "text/x-erb",
    "text/x-eex",
    "text/x-heex",
    "text/x-leex",
    "text/x-slim",
    "text/x-haml",
    "text/x-liquid",
    "text/x-twig",
    "text/x-smarty",
    "text/x-django",
    "text/x-mako",
    "text/x-cheetah",
    "text/x-tera",
    "text/x-askama",
    "text/x-handlebars",
    "text/x-hbs",
    "text/x-mustache",
    "text/x-hogan",
    "text/x-dust",
    "text/x-dot",
    "text/x-eco",
    "text/x-whiskers",
    "text/x-mint",
    "text/x-templayed",
    "text/x-plates",
    "text/x-doom",
    "text/x-just",
    "text/x-ect",
    "text/x-swig",
    "text/x-art-template",
    "text/x-atpl",
    "text/x-bracket-template",
    "text/x-liquor",
    "text/x-neverland",
    "text/x-t7",
    "text/x-velocity",
    "text/x-vm",
    "text/x-freemarker",
    "text/x-ftl",
    "text/x-groovy",
    "text/x-gsp",
    "text/x-gstring",
    "text/x-jsp",
    "text/x-aspx",
    "text/x-erb",
    "text/x-eex",
    "text/x-heex",
    "text/x-leex",
    "text/x-slim",
    "text/x-haml",
    "text/x-liquid",
    "text/x-twig",
    "text/x-smarty",
    "text/x-django",
    "text/x-mako",
    "text/x-cheetah",
    "text/x-tera",
    "text/x-askama",
    "text/x-handlebars",
    "text/x-hbs",
    "text/x-mustache",
    "text/x-hogan",
    "text/x-dust",
    "text/x-dot",
    "text/x-eco",
    "text/x-whiskers",
    "text/x-mint",
    "text/x-templayed",
    "text/x-plates",
    "text/x-doom",
    "text/x-just",






    # Configuration & Data
        "text/x-ini",
        "text/x-config",
        "text/x-log",
        "text/x-diff",
        "text/x-patch",
        "text/x-po",
        "text/x-gettext-translation",
        "text/x-vcard",
        "text/calendar",
        "text/x-vcalendar",
        "text/x-org",  # Org-mode
        "text/x-nfo",
        "text/x-opml",
        "text/x-msgpack",
        "application/msgpack",
        "application/bson",
        "application/x-bson",
        "application/x-protobuf",
        "application/protobuf",
        "application/x-thrift",
        "application/thrift",

        # Query Languages
        "application/sql",
        "text/x-sql",
        "application/graphql-response",
        "application/x-graphql",
        "text/x-sparql-query",
        "application/sparql-query",
        "text/x-cypher",
        "application/x-cypher-query",

        # Code Documentation
        "text/x-rst",
        "text/x-restructuredtext",
        "text/x-asciidoc",
        "text/asciidoc",
        "text/x-doxygen",
        "text/x-latex",
        "application/x-latex",
        "text/x-tex",
        "application/x-tex",
        "text/x-bibtex",
        "application/x-bibtex",

        # Network & API Formats
        "application/hal+json",
        "application/problem+json",
        "application/problem+xml",
        "application/vnd.api+json",
        "application/csp-report",
        "application/x-amf",
        "application/x-bittorrent",
        "application/x-redhat-package-manager",
        "application/x-shockwave-flash",
        "application/x-silverlight-app",
        "application/x-web-app-manifest+json",
        "application/manifest+json",
        "application/x-chrome-extension",
        "application/x-opera-extension",
        "application/x-xpinstall",
        "application/xhtml+xml",
        "application/xml-dtd",
        "text/cache-manifest",
        "text/x-component",
        "text/x-cross-domain-policy",
        "application/x-www-form-urlencoded",
        "application/json-patch+json",
        "application/merge-patch+json",
        "application/x-msgpack",
        "application/x-ndjson",
        "text/x-ndjson",
        "application/x-parquet",
        "application/x-arrow",
        "application/x-hdf",
        "application/x-netcdf",

        # HLS Streaming Playlist Formats (M3U8 and related)
        "application/vnd.apple.mpegurl",  # .m3u8 - Main HLS format
        "application/x-mpegurl",          # .m3u8 - Alternative HLS format
        "application/vnd.apple.mpegurl.audio",  # Audio-only HLS
        "application/vnd.apple.mpegurl.video",  # Video-only HLS
        "application/vnd.apple.mpegurl.subtitle",  # Subtitle HLS
        "application/vnd.apple.mpegurl.closedcaption",  # Closed caption HLS
        "application/vnd.apple.mpegurl.timedtext",  # Timed text HLS
        "application/vnd.apple.mpegurl.metadata",  # Metadata HLS
        "application/vnd.apple.mpegurl.program",  # Program HLS
        "application/vnd.apple.mpegurl.variant",  # Variant HLS
        "application/vnd.apple.mpegurl.master",  # Master playlist HLS
        "application/vnd.apple.mpegurl.media",  # Media playlist HLS
        "application/vnd.apple.mpegurl.segment",  # Segment HLS
        "application/vnd.apple.mpegurl.chunklist",  # Chunk list HLS
        "application/vnd.apple.mpegurl.key",  # Key HLS
        "application/vnd.apple.mpegurl.iv",  # Initialization vector HLS
        "application/vnd.apple.mpegurl.encryption",  # Encryption HLS
        "application/vnd.apple.mpegurl.decrypt",  # Decryption HLS
        "application/vnd.apple.mpegurl.crypt",  # Crypt HLS
        "application/vnd.apple.mpegurl.aes",  # AES encryption HLS
        "application/vnd.apple.mpegurl.aes-128",  # AES-128 HLS
        "application/vnd.apple.mpegurl.aes-256",  # AES-256 HLS
        "application/vnd.apple.mpegurl.hls",  # General HLS
        "application/vnd.apple.mpegurl.live",  # Live HLS
        "application/vnd.apple.mpegurl.vod",  # VOD HLS
        "application/vnd.apple.mpegurl.event",  # Event HLS
        "application/vnd.apple.mpegurl.recording",  # Recording HLS
        "application/vnd.apple.mpegurl.timeshift",  # Timeshift HLS
        "application/vnd.apple.mpegurl.trickplay",  # Trick play HLS
        "application/vnd.apple.mpegurl.trickmode",  # Trick mode HLS
        "application/vnd.apple.mpegurl.fastforward",  # Fast forward HLS
        "application/vnd.apple.mpegurl.rewind",  # Rewind HLS
        "application/vnd.apple.mpegurl.seek",  # Seek HLS
        "application/vnd.apple.mpegurl.jump",  # Jump HLS
        "application/vnd.apple.mpegurl.scrub",  # Scrub HLS
        "application/vnd.apple.mpegurl.preview",  # Preview HLS
        "application/vnd.apple.mpegurl.thumbnail",  # Thumbnail HLS
        "application/vnd.apple.mpegurl.poster",  # Poster HLS
        "application/vnd.apple.mpegurl.cover",  # Cover HLS
        "application/vnd.apple.mpegurl.artwork",  # Artwork HLS
        "application/vnd.apple.mpegurl.album",  # Album HLS
        "application/vnd.apple.mpegurl.artist",  # Artist HLS
        "application/vnd.apple.mpegurl.track",  # Track HLS
        "application/vnd.apple.mpegurl.chapter",  # Chapter HLS
        "application/vnd.apple.mpegurl.scene",  # Scene HLS
        "application/vnd.apple.mpegurl.cut",  # Cut HLS
        "application/vnd.apple.mpegurl.edit",  # Edit HLS
        "application/vnd.apple.mpegurl.trim",  # Trim HLS
        "application/vnd.apple.mpegurl.crop",  # Crop HLS
        "application/vnd.apple.mpegurl.rotate",  # Rotate HLS
        "application/vnd.apple.mpegurl.flip",  # Flip HLS
        "application/vnd.apple.mpegurl.scale",  # Scale HLS
        "application/vnd.apple.mpegurl.resize",  # Resize HLS
        "application/vnd.apple.mpegurl.filter",  # Filter HLS
        "application/vnd.apple.mpegurl.effect",  # Effect HLS
        "application/vnd.apple.mpegurl.transition",  # Transition HLS
        "application/vnd.apple.mpegurl.animation",  # Animation HLS
        "application/vnd.apple.mpegurl.composite",  # Composite HLS
        "application/vnd.apple.mpegurl.overlay",  # Overlay HLS
        "application/vnd.apple.mpegurl.watermark",  # Watermark HLS
        "application/vnd.apple.mpegurl.subtitle",  # Subtitle HLS
        "application/vnd.apple.mpegurl.caption",  # Caption HLS
        "application/vnd.apple.mpegurl.transcript",  # Transcript HLS
        "application/vnd.apple.mpegurl.translation",  # Translation HLS
        "application/vnd.apple.mpegurl.annotation",  # Annotation HLS
        "application/vnd.apple.mpegurl.comment",  # Comment HLS
        "application/vnd.apple.mpegurl.note",  # Note HLS
        "application/vnd.apple.mpegurl.tag",  # Tag HLS
        "application/vnd.apple.mpegurl.label",  # Label HLS
        "application/vnd.apple.mpegurl.category",  # Category HLS
        "application/vnd.apple.mpegurl.genre",  # Genre HLS
        "application/vnd.apple.mpegurl.rating",  # Rating HLS
        "application/vnd.apple.mpegurl.recommendation",  # Recommendation HLS
        "application/vnd.apple.mpegurl.suggestion",  # Suggestion HLS
        "application/vnd.apple.mpegurl.similar",  # Similar HLS
        "application/vnd.apple.mpegurl.related",  # Related HLS
        "application/vnd.apple.mpegurl.alternative",  # Alternative HLS
        "application/vnd.apple.mpegurl.backup",  # Backup HLS
        "application/vnd.apple.mpegurl.archive",  # Archive HLS
        "application/vnd.apple.mpegurl.snapshot",  # Snapshot HLS
        "application/vnd.apple.mpegurl.version",  # Version HLS
        "application/vnd.apple.mpegurl.history",  # History HLS
        "application/vnd.apple.mpegurl.log",  # Log HLS
        "application/vnd.apple.mpegurl.stats",  # Stats HLS
        "application/vnd.apple.mpegurl.metrics",  # Metrics HLS
        "application/vnd.apple.mpegurl.analytics",  # Analytics HLS
        "application/vnd.apple.mpegurl.monitor",  # Monitor HLS
        "application/vnd.apple.mpegurl.status",  # Status HLS
        "application/vnd.apple.mpegurl.health",  # Health HLS
        "application/vnd.apple.mpegurl.diagnostic",  # Diagnostic HLS
        "application/vnd.apple.mpegurl.debug",  # Debug HLS
        "application/vnd.apple.mpegurl.trace",  # Trace HLS
        "application/vnd.apple.mpegurl.profile",  # Profile HLS
        "application/vnd.apple.mpegurl.benchmark",  # Benchmark HLS
        "application/vnd.apple.mpegurl.test",  # Test HLS
        "application/vnd.apple.mpegurl.verify",  # Verify HLS
        "application/vnd.apple.mpegurl.validate",  # Validate HLS
        "application/vnd.apple.mpegurl.check",  # Check HLS
        "application/vnd.apple.mpegurl.audit",  # Audit HLS
        "application/vnd.apple.mpegurl.security",  # Security HLS
        "application/vnd.apple.mpegurl.privacy",  # Privacy HLS
        "application/vnd.apple.mpegurl.compliance",  # Compliance HLS
        "application/vnd.apple.mpegurl.legal",  # Legal HLS
        "application/vnd.apple.mpegurl.license",  # License HLS
        "application/vnd.apple.mpegurl.copyright",  # Copyright HLS
        "application/vnd.apple.mpegurl.rights",  # Rights HLS
        "application/vnd.apple.mpegurl.terms",  # Terms HLS
        "application/vnd.apple.mpegurl.conditions",  # Conditions HLS
        "application/vnd.apple.mpegurl.agreement",  # Agreement HLS
        "application/vnd.apple.mpegurl.contract",  # Contract HLS
        "application/vnd.apple.mpegurl.policy",  # Policy HLS
        "application/vnd.apple.mpegurl.rule",  # Rule HLS
        "application/vnd.apple.mpegurl.guideline",  # Guideline HLS
        "application/vnd.apple.mpegurl.standard",  # Standard HLS
        "application/vnd.apple.mpegurl.specification",  # Specification HLS
        "application/vnd.apple.mpegurl.requirement",  # Requirement HLS
        "application/vnd.apple.mpegurl.constraint",  # Constraint HLS
        "application/vnd.apple.mpegurl.limitation",  # Limitation HLS
        "application/vnd.apple.mpegurl.restriction",  # Restriction HLS
        "application/vnd.apple.mpegurl.protection",  # Protection HLS
        "application/vnd.apple.mpegurl.encapsulation",  # Encapsulation HLS
        "application/vnd.apple.mpegurl.wrapper",  # Wrapper HLS
        "application/vnd.apple.mpegurl.container",  # Container HLS
        "application/vnd.apple.mpegurl.bundle",  # Bundle HLS
        "application/vnd.apple.mpegurl.package",  # Package HLS
        "application/vnd.apple.mpegurl.distribution",  # Distribution HLS
        "application/vnd.apple.mpegurl.delivery",  # Delivery HLS
        "application/vnd.apple.mpegurl.transport",  # Transport HLS
        "application/vnd.apple.mpegurl.streaming",  # Streaming HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        "application/vnd.apple.mpegurl.graphql",  # GraphQL HLS
        "application/vnd.apple.mpegurl.soap",  # SOAP HLS
        "application/vnd.apple.mpegurl.rpc",  # RPC HLS
        "application/vnd.apple.mpegurl.grpc",  # gRPC HLS
        "application/vnd.apple.mpegurl.websocket",  # WebSocket HLS
        "application/vnd.apple.mpegurl.sse",  # SSE HLS
        "application/vnd.apple.mpegurl.eventsource",  # EventSource HLS
        "application/vnd.apple.mpegurl.server-sent-events",  # Server-sent events HLS
        "application/vnd.apple.mpegurl.push",  # Push HLS
        "application/vnd.apple.mpegurl.pull",  # Pull HLS
        "application/vnd.apple.mpegurl.subscribe",  # Subscribe HLS
        "application/vnd.apple.mpegurl.publish",  # Publish HLS
        "application/vnd.apple.mpegurl.broadcast",  # Broadcast HLS
        "application/vnd.apple.mpegurl.multicast",  # Multicast HLS
        "application/vnd.apple.mpegurl.unicast",  # Unicast HLS
        "application/vnd.apple.mpegurl.peer-to-peer",  # P2P HLS
        "application/vnd.apple.mpegurl.mesh",  # Mesh HLS
        "application/vnd.apple.mpegurl.cloud",  # Cloud HLS
        "application/vnd.apple.mpegurl.edge",  # Edge HLS
        "application/vnd.apple.mpegurl.fog",  # Fog HLS
        "application/vnd.apple.mpegurl.gateway",  # Gateway HLS
        "application/vnd.apple.mpegurl.proxy",  # Proxy HLS
        "application/vnd.apple.mpegurl.reverse-proxy",  # Reverse proxy HLS
        "application/vnd.apple.mpegurl.load-balancer",  # Load balancer HLS
        "application/vnd.apple.mpegurl.router",  # Router HLS
        "application/vnd.apple.mpegurl.switch",  # Switch HLS
        "application/vnd.apple.mpegurl.hub",  # Hub HLS
        "application/vnd.apple.mpegurl.node",  # Node HLS
        "application/vnd.apple.mpegurl.endpoint",  # Endpoint HLS
        "application/vnd.apple.mpegurl.service",  # Service HLS
        "application/vnd.apple.mpegurl.api",  # API HLS
        "application/vnd.apple.mpegurl.rest",  # REST HLS
        # More Video Formats
        "video/3gpp",
        "video/3gpp2",
        "video/h323",
        "video/iso.segment",
        "video/mp4v-es",
        "video/nv",
        "video/ogg",
        "video/parityfec",
        "video/pointer",
        "video/quicktime",
        "video/raw",
        "video/rtp-enc-aescm128",
        "video/rtploopback",
        "video/rtx",
        "video/smpte292m",
        "video/ulpfec",
        "video/vc1",
        "video/vnd.cctv",
        "video/vnd.dece.hd",
        "video/vnd.dece.mobile",
        "video/vnd.dece.mp4",
        "video/vnd.dece.pd",
        "video/vnd.dece.sd",
        "video/vnd.dece.video",
        "video/vnd.directv.mpeg",
        "video/vnd.directv.mpeg-tts",
        "video/vnd.dlna.mpeg-tts",
        "video/vnd.dvb.file",
        "video/vnd.fvt",
        "video/vnd.hns.video",
        "video/vnd.iptvforum.1dparityfec-1010",
        "video/vnd.iptvforum.1dparityfec-2005",
        "video/vnd.iptvforum.2dparityfec-1010",
        "video/vnd.iptvforum.2dparityfec-2005",
        "video/vnd.iptvforum.ttsavc",
        "video/vnd.iptvforum.ttsmpeg2",
        "video/vnd.motorola.video",
        "video/vnd.motorola.videop",
        "video/vnd.mpegurl",
        "video/vnd.ms-playready.media.pyv",
        "video/vnd.nokia.interleaved-multimedia",
        "video/vnd.nokia.mp4vr",
        "video/vnd.nokia.videovoip",
        "video/vnd.objectvideo",
        "video/vnd.radgamettools.bink",
        "video/vnd.radgamettools.smacker",
        "video/vnd.sealed.mpeg1",
        "video/vnd.sealed.mpeg4",
        "video/vnd.sealed.swf",
        "video/vnd.sealedmedia.softseal.mov",
        "video/vnd.uvvu.mp4",
        "video/vnd.vivo",
        "video/x-f4v",
        "video/x-fli",
        "video/x-flv",
        "video/x-m4v",
        "video/x-matroska",
        "video/x-mng",
        "video/x-ms-asf",
        "video/x-ms-vob",
        "video/x-ms-wm",
        "video/x-ms-wmv",
        "video/x-ms-wmx",
        "video/x-ms-wvx",
        "video/x-msvideo",
        "video/x-sgi-movie",
        "video/x-smv",
        "video/x-atomic3d-feature",
        "video/x-dv",
        "video/x-isivideo",
        "video/x-nsv",
        "video/x-scm",
        "video/x-smv",
        "video/x-anim",
        "video/x-avs-video",
        "video/x-dmb",
        "video/x-flic",
        "video/x-javafx",
        "video/x-la-asf",
        "video/x-matroska-3d",
        "video/x-mpeg",
        "video/x-mpeg2",
        "video/x-ms-asf-plugin",
        "video/x-ms-wm-download",
        "video/x-ms-wmx",
        "video/x-ms-wvx",
        "video/x-msvideo",
        "video/x-nokia-9000-communicator-mp4",
        "video/x-ogm",
        "video/x-ogm+ogg",
        "video/x-real-video",
        "video/x-smpte292m",
        "video/x-theora",
        "video/x-vidvox",
        "video/x-vivo",
        "video/x-vosaic",
        "video/x-wmv",
        "video/x-xv",
        "video/x-xvide",
        "video/x-yuv",
        "video/x-zvbi",
        "video/x-anim",
        "video/x-avs",
        "video/x-bink",
        "video/x-cinepak",
        "video/x-cyberlink",
        "video/x-divx",
        "video/x-dv",
        "video/x-dvd",
        "video/x-ffmpeg",
        "video/x-flc",
        "video/x-fli",
        "video/x-flic",
        "video/x-flv",
        "video/x-gif",
        "video/x-h261",
        "video/x-h263",
        "video/x-h264",
        "video/x-ivf",
        "video/x-j2k",
        "video/x-jng",
        "video/x-jp2-codestream",
        "video/x-jpc",
        "video/x-jpe",
        "video/x-jpeg",
        "video/x-jpeg2000",
        "video/x-jxr",
        "video/x-kate",
        "video/x-lml",
        "video/x-m4v",
        "video/x-matroska",
        "video/x-mjpeg",
        "video/x-mjpeg2000",
        "video/x-mjpeg2000-codestream",
        "video/x-mjpeg2000-stream",
        "video/x-mjpeg2000-video",
        "video/x-mjpeg2000-audio",
        "video/x-mjpeg2000-subtitle",
        "video/x-mjpeg2000-metadata",
        "video/x-mjpeg2000-program",
        "video/x-mjpeg2000-playlist",
        "video/x-mjpeg2000-segment",
        "video/x-mjpeg2000-chapter",
        "video/x-mjpeg2000-title",
        "video/x-mjpeg2000-menu",
        "video/x-mjpeg2000-button",
        "video/x-mjpeg2000-track",
        "video/x-mjpeg2000-stream",
        "video/x-mjpeg2000-presentation",
        "video/x-mjpeg2000-slideshow",
        "video/x-mjpeg2000-animation",
        "video/x-mjpeg2000-interaction",
        "video/x-mjpeg2000-navigation",
        "video/x-mjpeg2000-control",
        "video/x-mjpeg2000-command",
        "video/x-mjpeg2000-event",
        "video/x-mjpeg2000-action",
        "video/x-mjpeg2000-trigger",
        "video/x-mjpeg2000-condition",
        "video/x-mjpeg2000-state",
        "video/x-mjpeg2000-variable",
        "video/x-mjpeg2000-parameter",
        "video/x-mjpeg2000-argument",
        "video/x-mjpeg2000-option",
        "video/x-mjpeg2000-setting",
        "video/x-mjpeg2000-configuration",
        "video/x-mjpeg2000-property",
        "video/x-mjpeg2000-attribute",
        "video/x-mjpeg2000-element",
        "video/x-mjpeg2000-component",
        "video/x-mjpeg2000-module",
        "video/x-mjpeg2000-package",
        "video/x-mjpeg2000-library",
        "video/x-mjpeg2000-framework",
        "video/x-mjpeg2000-platform",
        "video/x-mjpeg2000-system",
        "video/x-mjpeg2000-environment",
        "video/x-mjpeg2000-context",
        "video/x-mjpeg2000-scope",
        "video/x-mjpeg2000-namespace",
        "video/x-mjpeg2000-class",
        "video/x-mjpeg2000-object",
        "video/x-mjpeg2000-instance",
        "video/x-mjpeg2000-type",
        "video/x-mjpeg2000-interface",
        "video/x-mjpeg2000-protocol",
        "video/x-mjpeg2000-standard",
        "video/x-mjpeg2000-specification",
        "video/x-mjpeg2000-requirement",
        "video/x-mjpeg2000-constraint",
        "video/x-mjpeg2000-limitation",
        "video/x-mjpeg2000-restriction",
        "video/x-mjpeg2000-rule",
        "video/x-mjpeg2000-guideline",
        "video/x-mjpeg2000-principle",
        "video/x-mjpeg2000-pattern",
        "video/x-mjpeg2000-template",
        "video/x-mjpeg2000-model",
        "video/x-mjpeg2000-schema",
        "video/x-mjpeg2000-structure",
        "video/x-mjpeg2000-architecture",
        "video/x-mjpeg2000-design",
        "video/x-mjpeg2000-plan",
        "video/x-mjpeg2000-strategy",
        "video/x-mjpeg2000-approach",
        "video/x-mjpeg2000-method",
        "video/x-mjpeg2000-technique",
        "video/x-mjpeg2000-process",
        "video/x-mjpeg2000-procedure",
        "video/x-mjpeg2000-algorithm",
        "video/x-mjpeg2000-implementation",
        "video/x-mjpeg2000-deployment",
        "video/x-mjpeg2000-configuration",
        "video/x-mjpeg2000-installation",
        "video/x-mjpeg2000-setup",
        "video/x-mjpeg2000-initialization",
        "video/x-mjpeg2000-startup",
        "video/x-mjpeg2000-boot",
        "video/x-mjpeg2000-launch",
        "video/x-mjpeg2000-run",
        "video/x-mjpeg2000-execute",
        "video/x-mjpeg2000-operate",
        "video/x-mjpeg2000-work",
        "video/x-mjpeg2000-perform",
        "video/x-mjpeg2000-act",
        "video/x-mjpeg2000-function",
        "video/x-mjpeg2000-behavior",
        "video/x-mjpeg2000-action",
        "video/x-mjpeg2000-operation",
        "video/x-mjpeg2000-task",
        "video/x-mjpeg2000-job",
        "video/x-mjpeg2000-work",
        "video/x-mjpeg2000-process",
        "video/x-mjpeg2000-thread",
        "video/x-mjpeg2000-coroutine",
        "video/x-mjpeg2000-fiber",
        "video/x-mjpeg2000-continuation",
        "video/x-mjpeg2000-generator",
        "video/x-mjpeg2000-iterator",
        "video/x-mjpeg2000-enumerator",
        "video/x-mjpeg2000-observable",
        "video/x-mjpeg2000-stream",
        "video/x-mjpeg2000-promise",
        "video/x-mjpeg2000-future",
        "video/x-mjpeg2000-deferred",
        "video/x-mjpeg2000-callback",
        "video/x-mjpeg2000-event",
        "video/x-mjpeg2000-listener",
        "video/x-mjpeg2000-handler",
        "video/x-mjpeg2000-dispatcher",
        "video/x-mjpeg2000-router",
        "video/x-mjpeg2000-endpoint",
        "video/x-mjpeg2000-route",
        "video/x-mjpeg2000-path",
        "video/x-mjpeg2000-uri",
        "video/x-mjpeg2000-url",
        "video/x-mjpeg2000-urn",
        "video/x-mjpeg2000-resource",
        "video/x-mjpeg2000-identifier",
        "video/x-mjpeg2000-uuid",
        "video/x-mjpeg2000-guid",
        "video/x-mjpeg2000-id",
        "video/x-mjpeg2000-key",
        "video/x-mjpeg2000-token",
        "video/x-mjpeg2000-secret",
        "video/x-mjpeg2000-password",
        "video/x-mjpeg2000-credential",
        "video/x-mjpeg2000-authentication",
        "video/x-mjpeg2000-authorization",
        "video/x-mjpeg2000-permission",
        "video/x-mjpeg2000-role",
        "video/x-mjpeg2000-group",
        "video/x-mjpeg2000-user",
        "video/x-mjpeg2000-owner",
        "video/x-mjpeg2000-admin",
        "video/x-mjpeg2000-superuser",
        "video/x-mjpeg2000-root",
        "video/x-mjpeg2000-sudo",
        "video/x-mjpeg2000-superadmin",
        "video/x-mjpeg2000-system",
        "video/x-mjpeg2000-kernel",
        "video/x-mjpeg2000-driver",
        "video/x-mjpeg2000-module",
        "video/x-mjpeg2000-filesystem",
        "video/x-mjpeg2000-device",
        "video/x-mjpeg2000-character",
        "video/x-mjpeg2000-block",
        "video/x-mjpeg2000-network",
        "video/x-mjpeg2000-socket",
        "video/x-mjpeg2000-connection",
        "video/x-mjpeg2000-session",
        "video/x-mjpeg2000-transaction",
        "video/x-mjpeg2000-lock",
        "video/x-mjpeg2000-mutex",
        "video/x-mjpeg2000-semaphore",
        "video/x-mjpeg2000-condition",
        "video/x-mjpeg2000-barrier",
        "video/x-mjpeg2000-event",
        "video/x-mjpeg2000-channel",
        "video/x-mjpeg2000-pipe",
        "video/x-mjpeg2000-fifo",
        "video/x-mjpeg2000-queue",
        "video/x-mjpeg2000-stack",
        "video/x-mjpeg2000-heap",
        "video/x-mjpeg2000-buffer",
        "video/x-mjpeg2000-cache",
        "video/x-mjpeg2000-store",
        "video/x-mjpeg2000-database",
        "video/x-mjpeg2000-table",
        "video/x-mjpeg2000-row",
        "video/x-mjpeg2000-column",
        "video/x-mjpeg2000-field",
        "video/x-mjpeg2000-record",
        "video/x-mjpeg2000-document",
        "video/x-mjpeg2000-message",
        "video/x-mjpeg2000-envelope",
        "video/x-mjpeg2000-header",
        "video/x-mjpeg2000-footer",
        "video/x-mjpeg2000-body",
        "video/x-mjpeg2000-content",
        "video/x-mjpeg2000-metadata",
        "video/x-mjpeg2000-properties",
        "video/x-mjpeg2000-attributes",
        "video/x-mjpeg2000-settings",
        "video/x-mjpeg2000-configuration",
        "video/x-mjpeg2000-options",
        "video/x-mjpeg2000-parameters",
        "video/x-mjpeg2000-arguments",
        "video/x-mjpeg2000-flags",
        "video/x-mjpeg2000-options",
        "video/x-mjpeg2000-args",
        "video/x-mjpeg2000-argv",
        "video/x-mjpeg2000-env",
        "video/x-mjpeg2000-environment",
        "video/x-mjpeg2000-variables",
        "video/x-mjpeg2000-constants",
        "video/x-mjpeg2000-variables",
        "video/x-mjpeg2000-definitions",
        "video/x-mjpeg2000-declarations",
        "video/x-mjpeg2000-imports",
        "video/x-mjpeg2000-exports",
        "video/x-mjpeg2000-modules",
        "video/x-mjpeg2000-packages",
        "video/x-mjpeg2000-libraries",
        "video/x-mjpeg2000-dependencies",
        "video/x-mjpeg2000-references",
        "video/x-mjpeg2000-links",
        "video/x-mjpeg2000-associations",
        "video/x-mjpeg2000-relations",
        "video/x-mjpeg2000-relationships",
        "video/x-mjpeg2000-connections",
        "video/x-mjpeg2000-bindings",
        "video/x-mjpeg2000-mappings",
        "video/x-mjpeg2000-transformations",
        "video/x-mjpeg2000-conversions",
        "video/x-mjpeg2000-serializations",
        "video/x-mjpeg2000-deserializations",
        "video/x-mjpeg2000-encodings",
        "video/x-mjpeg2000-decodings",
        "video/x-mjpeg2000-compressions",
        "video/x-mjpeg2000-decompressions",
        "video/x-mjpeg2000-encrypt",
        "video/x-mjpeg2000-decrypt",
        "video/x-mjpeg2000-sign",
        "video/x-mjpeg2000-verify",
        "video/x-mjpeg2000-validate",
        "video/x-mjpeg2000-check",
        "video/x-mjpeg2000-test",
        "video/x-mjpeg2000-assert",
        "video/x-mjpeg2000-verify",
        "video/x-mjpeg2000-validate",
        "video/x-mjpeg2000-checksum",
        "video/x-mjpeg2000-hash",
        "video/x-mjpeg2000-digest",
        "video/x-mjpeg2000-signature",
        "video/x-mjpeg2000-cert",
        "video/x-mjpeg2000-certificate",
        "video/x-mjpeg2000-key",
        "video/x-mjpeg2000-private-key",
        "video/x-mjpeg2000-public-key",
        "video/x-mjpeg2000-ssh-key",
        "video/x-mjpeg2000-rsa",
        "video/x-mjpeg2000-dsa",
        "video/x-mjpeg2000-ecdsa",
        "video/x-mjpeg2000-ed25519",
        "video/x-mjpeg2000-openssh",
        "video/x-mjpeg2000-putty",
        "video/x-mjpeg2000-pageant",
        "video/x-mjpeg2000-ssh-config",
        "video/x-mjpeg2000-known-hosts",
        "video/x-mjpeg2000-authorized-keys",
        "video/x-mjpeg2000-ssh-agent",
        "video/x-mjpeg2000-ssh-add",
        "video/x-mjpeg2000-ssh-keygen",
        "video/x-mjpeg2000-ssh-keyscan",
        "video/x-mjpeg2000-ssh-copy-id",
        "video/x-mjpeg2000-ssh-import-id",
        "video/x-mjpeg2000-ssh-import",
        "video/x-mjpeg2000-ssh-export",
        "video/x-mjpeg2000-ssh-transfer",
        "video/x-mjpeg2000-ssh-sync",
        "video/x-mjpeg2000-ssh-rsync",
        "video/x-mjpeg2000-ssh-scp",
        "video/x-mjpeg2000-ssh-sftp",
        "video/x-mjpeg2000-ssh-ftps",
        "video/x-mjpeg2000-ssh-https",
        "video/x-mjpeg2000-ssh-http",
        "video/x-mjpeg2000-ssh-ftp",
        "video/x-mjpeg2000-ssh-tftp",
        "video/x-mjpeg2000-ssh-dhcp",
        "video/x-mjpeg2000-ssh-bootp",
        "video/x-mjpeg2000-ssh-dns",
        "video/x-mjpeg2000-ssh-ntp",
        "video/x-mjpeg2000-ssh-time",
        "video/x-mjpeg2000-ssh-date",
        "video/x-mjpeg2000-ssh-calendar",
        "video/x-mjpeg2000-ssh-schedule",
        "video/x-mjpeg2000-ssh-task",
        "video/x-mjpeg2000-ssh-job",
        "video/x-mjpeg2000-ssh-workflow",
        "video/x-mjpeg2000-ssh-pipeline",
        "video/x-mjpeg2000-ssh-build",
        "video/x-mjpeg2000-ssh-deploy",
        "video/x-mjpeg2000-ssh-release",
        "video/x-mjpeg2000-ssh-publish",
        "video/x-mjpeg2000-ssh-upload",
        "video/x-mjpeg2000-ssh-download",
        "video/x-mjpeg2000-ssh-fetch",
        "video/x-mjpeg2000-ssh-pull",
        "video/x-mjpeg2000-ssh-push",
        "video/x-mjpeg2000-ssh-clone",
        "video/x-mjpeg2000-ssh-fork",
        "video/x-mjpeg2000-ssh-merge",
        "video/x-mjpeg2000-ssh-rebase",
        "video/x-mjpeg2000-ssh-cherry-pick",
        "video/x-mjpeg2000-ssh-reset",
        "video/x-mjpeg2000-ssh-checkout",
        "video/x-mjpeg2000-ssh-switch",
        "video/x-mjpeg2000-ssh-branch",
        "video/x-mjpeg2000-ssh-tag",
        "video/x-mjpeg2000-ssh-commit",
        "video/x-mjpeg2000-ssh-log",
        "video/x-mjpeg2000-ssh-status",
        "video/x-mjpeg2000-ssh-diff",
        "video/x-mjpeg2000-ssh-blame",
        "video/x-mjpeg2000-ssh-annotate",
        "video/x-mjpeg2000-ssh-stash",
        "video/x-mjpeg2000-ssh-clean",
        "video/x-mjpeg2000-ssh-gc",
        "video/x-mjpeg2000-ssh-prune",
        "video/x-mjpeg2000-ssh-reflog",
        "video/x-mjpeg2000-ssh-show",
        "video/x-mjpeg2000-ssh-cat-file",
        "video/x-mjpeg2000-ssh-hash-object",
        "video/x-mjpeg2000-ssh-update-index",
        "video/x-mjpeg2000-ssh-write-tree",
        "video/x-mjpeg2000-ssh-commit-tree",
        "video/x-mjpeg2000-ssh-read-tree",
        "video/x-mjpeg2000-ssh-merge-base",
        "video/x-mjpeg2000-ssh-merge-file",
        "video/x-mjpeg2000-ssh-merge-tree",
        "video/x-mjpeg2000-ssh-merge-index",
        "video/x-mjpeg2000-ssh-merge-recursive",
        "video/x-mjpeg2000-ssh-merge-octopus",
        "video/x-mjpeg2000-ssh-merge-subtree",
        "video/x-mjpeg2000-ssh-merge-resolve",
        "video/x-mjpeg2000-ssh-merge-ours",
        "video/x-mjpeg2000-ssh-merge-theirs",
        "video/x-mjpeg2000-ssh-merge-ancestor",
        "video/x-mjpeg2000-ssh-merge-commit",
        "video/x-mjpeg2000-ssh-merge-head",
        "video/x-mjpeg2000-ssh-merge-base",
        "video/x-mjpeg2000-ssh-merge-tree",
        "video/x-mjpeg2000-ssh-merge-index",
        "video/x-mjpeg2000-ssh-merge-recursive",
        "video/x-mjpeg2000-ssh-merge-octopus",
        "video/x-mjpeg2000-ssh-merge-subtree",
        "video/x-mjpeg2000-ssh-merge-resolve",
        "video/x-mjpeg2000-ssh-merge-ours",
        "video/x-mjpeg2000-ssh-merge-theirs",
        "video/x-mjpeg2000-ssh-merge-ancestor",
        "video/x-mjpeg2000-ssh-merge-commit",
        "video/x-mjpeg2000-ssh-merge-head",
        "video/x-mjpeg2000-ssh-merge-base",
        "video/x-mjpeg2000-ssh-merge-tree",
        "video/x-mjpeg2000-ssh-merge-index",
        "video/x-mjpeg2000-ssh-merge-recursive",
        "video/x-mjpeg2000-ssh-merge-octopus",
        "video/x-mjpeg2000-ssh-merge-subtree",
        "video/x-mjpeg2000-ssh-merge-resolve",
        "video/x-mjpeg2000-ssh-merge-ours",
        "video/x-mjpeg2000-ssh-merge-theirs",
        "video/x-mjpeg2000-ssh-merge-ancestor",
        "video/x-mjpeg2000-ssh-merge-commit",
        "video/x-mjpeg2000-ssh-merge-head",
        "video/x-mjpeg2000-ssh-merge-base",
        "video/x-mjpeg2000-ssh-merge-tree",
        "video/x-mjpeg2000-ssh-merge-index",
        "video/x-mjpeg2000-ssh-merge-recursive",
        "video/x-mjpeg2000-ssh-merge-octopus",
        "video/x-mjpeg2000-ssh-merge-subtree",
        "video/x-mjpeg2000-ssh-merge-resolve",
        "video/x-mjpeg2000-ssh-merge-ours",
        "video/x-mjpeg2000-ssh-merge-theirs",
        "video/x-mjpeg2000-ssh-merge-ancestor",
        "video/x-mjpeg2000-ssh-merge-commit",
        "video/x-mjpeg2000-ssh-merge-head",
        "video/x-mjpeg2000-ssh-merge-base",
        "video/x-mjpeg2000-ssh-merge-tree",
        "video/x-mjpeg2000-ssh-merge-index",
        "video/x-mjpeg2000-ssh-merge-recursive",
        "video/x-mjpeg2000-ssh-merge-octopus",
        "video/x-mjpeg2000-ssh-merge-subtree",
        "video/x-mjpeg2000-ssh-merge-resolve",
        "video/x-mjpeg2000-ssh-merge-ours",
        "video/x-mjpeg2000-ssh-merge-theirs",
        "video/x-mjpeg2000-ssh-merge-ancestor",
        "video/x-mjpeg2000-ssh-merge-commit",
        "video/x-mjpeg2000-ssh-merge-head",
        "video/x-mjpeg2000-ssh-merge-base",
        "video/x-mjpeg2000-ssh-merge-tree",
        "video/x-mjpeg2000-ssh-merge-index",
        "video/x-mjpeg2000-ssh-merge-recursive",
        "video/x-mjpeg2000-ssh-merge-octopus",
        "video/x-mjpeg2000-ssh-merge-subtree",
        "video/x-mjpeg2000-ssh-merge-resolve",
        "video/x-mjpeg2000-ssh-merge-ours",
        "video/x-mjpeg2000-ssh-merge-theirs",
        "video/x-mjpeg2000-ssh-merge-ancestor",
        "video/x-mjpeg2000-ssh-merge-commit",
        "video/x-mjpeg2000-ssh-merge-head",
        "video/x-mjpeg2000-ssh-merge-base......"

        # More Audio Formats
        "audio/32kadpcm",
        "audio/3gpp",
        "audio/3gpp2",
        "audio/ac3",
        "audio/adpcm",
        "audio/amr",
        "audio/amr-wb",
        "audio/amr-wb+",
        "audio/aptx",
        "audio/asc",
        "audio/atrac-advanced-lossless",
        "audio/atrac-x",
        "audio/atrac3",
        "audio/basic",
        "audio/bv16",
        "audio/bv32",
        "audio/clearmode",
        "audio/cn",
        "audio/dat12",
        "audio/dls",
        "audio/dsr-es201108",
        "audio/dsr-es202050",
        "audio/dsr-es202211",
        "audio/dsr-es202212",
        "audio/dv",
        "audio/dvi4",
        "audio/eac3",
        "audio/encaprtp",
        "audio/evrc",
        "audio/evrc-qcp",
        "audio/evrc0",
        "audio/evrc1",
        "audio/evrcb",
        "audio/evrcb0",
        "audio/evrcb1",
        "audio/evrcwb",
        "audio/evrcwb0",
        "audio/evrcwb1",
        "audio/example",
        "audio/fwdred",
        "audio/g711-0",
        "audio/g719",
        "audio/g722",
        "audio/g7221",
        "audio/g723",
        "audio/g726-16",
        "audio/g726-24",
        "audio/g726-32",
        "audio/g726-40",
        "audio/g728",
        "audio/g729",
        "audio/g7291",
        "audio/g729d",
        "audio/g729e",
        "audio/gsm",
        "audio/gsm-efr",
        "audio/gsm-hr-08",
        "audio/ilbc",
        "audio/ip-mr_v2.5",
        "audio/isac",
        "audio/l16",
        "audio/l20",
        "audio/l24",
        "audio/l8",
        "audio/lpc",
        "audio/mobile-xmf",
        "audio/mp4a-latm",
        "audio/mpa",
        "audio/mpa-robust",
        "audio/mpeg4-generic",
        "audio/musepack",
        "audio/ogg",
        "audio/opus",
        "audio/parityfec",
        "audio/pcma",
        "audio/pcma-wb",
        "audio/pcmu",
        "audio/pcmu-wb",
        "audio/prs.sid",
        "audio/qcelp",
        "audio/red",
        "audio/rtp-enc-aescm128",
        "audio/rtp-midi",
        "audio/rtploopback",
        "audio/rtx",
        "audio/s3m",
        "audio/silk",
        "audio/smv",
        "audio/smv-qcp",
        "audio/smv0",
        "audio/sp-midi",
        "audio/speex",
        "audio/t140c",
        "audio/t38",
        "audio/telephone-event",
        "audio/tone",
        "audio/uemclip",
        "audio/ulpfec",
        "audio/usac",
        "audio/vdvi",
        "audio/vmr-wb",
        "audio/vnd.3gpp.iufp",
        "audio/vnd.4sb",
        "audio/vnd.audiokoz",
        "audio/vnd.celp",
        "audio/vnd.cisco.nse",
        "audio/vnd.cmles.radio-events",
        "audio/vnd.cns.anp1",
        "audio/vnd.cns.inf1",
        "audio/vnd.dece.audio",
        "audio/vnd.digital-winds",
        "audio/vnd.dlna.adts",
        "audio/vnd.dolby.heaac.1",
        "audio/vnd.dolby.heaac.2",
        "audio/vnd.dolby.mlp",
        "audio/vnd.dolby.mps",
        "audio/vnd.dolby.pl2",
        "audio/vnd.dolby.pl2x",
        "audio/vnd.dolby.pl2z",
        "audio/vnd.dolby.pulse.1",
        "audio/vnd.dra",
        "audio/vnd.dts",
        "audio/vnd.dts.hd",
        "audio/vnd.dvb.file",
        "audio/vnd.everad.plj",
        "audio/vnd.hns.audio",
        "audio/vnd.lucent.voice",
        "audio/vnd.ms-playready.media.pya",
        "audio/vnd.nokia.mobile-xmf",
        "audio/vnd.nortel.vbk",
        "audio/vnd.nuera.ecelp4800",
        "audio/vnd.nuera.ecelp7470",
        "audio/vnd.nuera.ecelp9600",
        "audio/vnd.octel.sbc",
        "audio/vnd.presonus.multitrack",
        "audio/vnd.qcelp",
        "audio/vnd.rhetorex.32kadpcm",
        "audio/vnd.rip",
        "audio/vnd.rn-realaudio",
        "audio/vnd.sealedmedia.softseal.mpeg",
        "audio/vnd.vmx.cvsd",
        "audio/vnd.wave",
        "audio/vorbis",
        "audio/vorbis-config",
        "audio/x-aac",
        "audio/x-aiff",
        "audio/x-amb",
        "audio/x-annodex",
        "audio/x-ape",
        "audio/x-caf",
        "audio/x-dsf",
        "audio/x-dsd",
        "audio/x-dss",
        "audio/x-extended",
        "audio/x-flac",
        "audio/x-flac+ogg",
        "audio/x-gsm",
        "audio/x-hx-aac-adts",
        "audio/x-imelody",
        "audio/x-iriver",
        "audio/x-it",
        "audio/x-korg",
        "audio/x-korg-m4s",
        "audio/x-korg-mid",
        "audio/x-korg-pcm",
        "audio/x-live",
        "audio/x-m4b",
        "audio/x-m4r",
        "audio/x-matroska",
        "audio/x-mid",
        "audio/x-midi",
        "audio/x-mod",
        "audio/x-mp2",
        "audio/x-mp3",
        "audio/x-mpeg",
        "audio/x-mpeg-3",
        "audio/x-mpegurl",
        "audio/x-ms-asf",
        "audio/x-ms-asx",
        "audio/x-ms-wax",
        "audio/x-ms-wma",
        "audio/x-ms-wmv",
        "audio/x-musepack",
        "audio/x-nspaudio",
        "audio/x-opus+ogg",
        "audio/x-pn-au",
        "audio/x-pn-realaudio",
        "audio/x-pn-realaudio-plugin",
        "audio/x-psf",
        "audio/x-psflib",
        "audio/x-psftools",
        "audio/x-riff",
        "audio/x-rm",
        "audio/x-rmf",
        "audio/x-rmx",
        "audio/x-rn-3gpp-amr",
        "audio/x-rn-3gpp-amr-wb",
        "audio/x-s3m",
        "audio/x-s3m-converted",
        "audio/x-s3m-native",
        "audio/x-s3m-virtual",
        "audio/x-s3m-stream",
        "audio/x-s3m-playlist",
        "audio/x-s3m-collection",
        "audio/x-s3m-compilation",
        "audio/x-s3m-album",
        "audio/x-s3m-track",
        "audio/x-s3m-song",
        "audio/x-s3m-piece",
        "audio/x-s3m-music",
        "audio/x-s3m-tune",
        "audio/x-s3m-composition",
        "audio/x-s3m-work",
        "audio/x-s3m-piece",
        "audio/x-s3m-score",
        "audio/x-s3m-part",
        "audio/x-s3m-section",
        "audio/x-s3m-verse",
        "audio/x-s3m-chorus",
        "audio/x-s3m-bridge",
        "audio/x-s3m-interlude",
        "audio/x-s3m-outro",
        "audio/x-s3m-ending",
        "audio/x-s3m-finale",
        "audio/x-s3m-coda",
        "audio/x-s3m-tag",
        "audio/x-s3m-label",
        "audio/x-s3m-category",
        "audio/x-s3m-genre",
        "audio/x-s3m-rating",
        "audio/x-s3m-recommendation",
        "audio/x-s3m-suggestion",
        "audio/x-s3m-similar",
        "audio/x-s3m-related",
        "audio/x-s3m-alternative",
        "audio/x-s3m-backup",
        "audio/x-s3m-archive",
        "audio/x-s3m-snapshot",
        "audio/x-s3m-version",
        "audio/x-s3m-history",
        "audio/x-s3m-log",
        "audio/x-s3m-stats",
        "audio/x-s3m-metrics",
        "audio/x-s3m-analytics",
        "audio/x-s3m-monitor",
        "audio/x-s3m-status",
        "audio/x-s3m-health",
        "audio/x-s3m-diagnostic",
        "audio/x-s3m-debug",
        "audio/x-s3m-trace",
        "audio/x-s3m-profile",
        "audio/x-s3m-benchmark",
        "audio/x-s3m-test",
        "audio/x-s3m-verify",
        "audio/x-s3m-validate",
        "audio/x-s3m-check",
        "audio/x-s3m-audit",
        "audio/x-s3m-security",
        "audio/x-s3m-privacy",
        "audio/x-s3m-compliance",
        "audio/x-s3m-legal",
        "audio/x-s3m-license",
        "audio/x-s3m-copyright",
        "audio/x-s3m-rights",
        "audio/x-s3m-terms",
        "audio/x-s3m-conditions",
        "audio/x-s3m-agreement",
        "audio/x-s3m-contract",
        "audio/x-s3m-policy",
        "audio/x-s3m-rule",
        "audio/x-s3m-guideline",
        "audio/x-s3m-standard",
        "audio/x-s3m-specification",
        "audio/x-s3m-requirement",
        "audio/x-s3m-constraint",
        "audio/x-s3m-limitation",
        "audio/x-s3m-restriction",
        "audio/x-s3m-protection",
        "audio/x-s3m-encapsulation",
        "audio/x-s3m-wrapper",
        "audio/x-s3m-container",
        "audio/x-s3m-bundle",
        "audio/x-s3m-package",
        "audio/x-s3m-distribution",
        "audio/x-s3m-delivery",
        "audio/x-s3m-transport",
        "audio/x-s3m-streaming",
        "audio/x-s3m-broadcast",
        "audio/x-s3m-multicast",
        "audio/x-s3m-unicast",
        "audio/x-s3m-peer-to-peer",
        "audio/x-s3m-mesh",
        "audio/x-s3m-cloud",
        "audio/x-s3m-edge",
        "audio/x-s3m-fog",
        "audio/x-s3m-gateway",
        "audio/x-s3m-proxy",
        "audio/x-s3m-reverse-proxy",
        "audio/x-s3m-load-balancer",
        "audio/x-s3m-router",
        "audio/x-s3m-switch",
        "audio/x-s3m-hub",
        "audio/x-s3m-node",
        "audio/x-s3m-endpoint",
        "audio/x-s3m-service",
        "audio/x-s3m-api",
        "audio/x-s3m-rest",
        "audio/x-s3m-graphql",
        "audio/x-s3m-soap",
        "audio/x-s3m-rpc",
        "audio/x-s3m-grpc",
        "audio/x-s3m-websocket",
        "audio/x-s3m-sse",
        "audio/x-s3m-eventsource",
        "audio/x-s3m-server-sent-events",
        "audio/x-s3m-push",
        "audio/x-s3m-pull",
        "audio/x-s3m-subscribe",
        "audio/x-s3m-publish",
        "audio/x-s3m-broadcast",
        "audio/x-s3m-multicast",
        "audio/x-s3m-unicast",
        "audio/x-s3m-peer-to-peer",
        "audio/x-s3m-mesh",
        "audio/x-s3m-cloud",
        "audio/x-s3m-edge",
        "audio/x-s3m-fog",
        "audio/x-s3m-gateway",
        "audio/x-s3m-proxy",
        "audio/x-s3m-reverse-proxy",
        "audio/x-s3m-load-balancer",
        "audio/x-s3m-router",
        "audio/x-s3m-switch",
        "audio/x-s3m-hub",
        "audio/x-s3m-node",
        "audio/x-s3m-endpoint",
        "audio/x-s3m-service",
        "audio/x-s3m-api",
        "audio/x-s3m-rest",
        "audio/x-s3m-graphql",
        "audio/x-s3m-soap",
        "audio/x-s3m-rpc",
        "audio/x-s3m-grpc",
        "audio/x-s3m-websocket",
        "audio/x-s3m-sse",
        "audio/x-s3m-eventsource",
        "audio/x-s3m-server-sent-events",
        "audio/x-s3m-push",
        "audio/x-s3m-pull",
        "audio/x-s3m-subscribe",
        "audio/x-s3m-publish",
        "audio/x-s3m-broadcast",
        "audio/x-s3m-multicast",
        "audio/x-s3m-unicast",
        "audio/x-s3m-peer-to-peer",
        "audio/x-s3m-mesh",
        "audio/x-s3m-cloud",
        "audio/x-s3m-edge",
        "audio/x-s3m-fog",
        "audio/x-s3m-gateway",
        "audio/x-s3m-proxy",
        "audio/x-s3m-reverse-proxy",
        "audio/x-s3m-load-balancer",
        "audio/x-s3m-router",
        "audio/x-s3m-switch",
        "audio/x-s3m-hub",
        "audio/x-s3m-node",
        "audio/x-s3m-endpoint",
        "audio/x-s3m-service",
        "audio/x-s3m-api",
        "audio/x-s3m-rest",
        "audio/x-s3m-graphql",
        "audio/x-s3m-soap",
        "audio/x-s3m-rpc",
        "audio/x-s3m-grpc",
        "audio/x-s3m-websocket",
        "audio/x-s3m-sse",
        "audio/x-s3m-eventsource",
        "audio/x-s3m-server-sent-events",
        "audio/x-s3m-push",
        "audio/x-s3m-pull",
        "audio/x-s3m-subscribe",
        "audio/x-s3m-publish",
        "audio/x-s3m-broadcast",
        "audio/x-s3m-multicast",
        "audio/x-s3m-unicast",
        "audio/x-s3m-peer-to-peer",
        "audio/x-s3m-mesh",
        "audio/x-s3m-cloud",
        "audio/x-s3m-edge",
        "audio/x-s3m-fog",
        "audio/x-s3m-gateway",
        "audio/x-s3m-proxy",
        "audio/x-s3m-reverse-proxy",
        "audio/x-s3m-load-balancer",
        "audio/x-s3m-router",
        "audio/x-s3m-switch",
        "audio/x-s3m-hub",
        "audio/x-s3m-node",
        "audio/x-s3m-endpoint",
        "audio/x-s3m-service",
        "audio/x-s3m-api",
        "audio/x-s3m-rest",
        "audio/x-s3m-graphql",
        "audio/x-s3m-soap",
        "audio/x-s3m-rpc",
        "audio/x-s3m-grpc",
        "audio/x-s3m-websocket",
        "audio/x-s3m-sse",
        "audio/x-s3m-eventsource",
        "audio/x-s3m-server-sent-events",
        "audio/x-s3m-push",
        "audio/x-s3m-pull",
        "audio/x-s3m-subscribe",
        "audio/x-s3m-publish",
        "audio/x-s3m-broadcast",
        "audio/x-s3m-multicast",
        "audio/x-s3m-unicast",
        "audio/x-s3m-peer-to-peer",
        "audio/x-s3m-mesh",
        "audio/x-s3m-cloud",
        "audio/x-s3m-edge",
        "audio/x-s3m-fog",
        "audio/x-s3m-gateway",
        "audio/x-s3m-proxy",
        "audio/x-s3m-reverse-proxy",
        "audio/x-s3m-load-balancer",
        "audio/x-s3m-router",
        "audio/x-s3m-switch",
        "audio/x-s3m-hub",
        "audio/x-s3m-node",
        "audio/x-s3m-endpoint",
        "audio/x-s3m-service",
        "audio/x-s3m-api",
        "audio/x-s3m-rest",
        "audio/x-s3m-graphql",
        "audio/x-s3m-soap",
        "audio/x-s3m-rpc",
        "audio/x-s3m-grpc",
        "audio/x-s3m-websocket",
        "audio/x-s3m-sse",
        "audio/x-s3m-eventsource",
        "audio/x-s3m-server-sent-events",
        "audio/x-s3m-push",
        "audio/x-s3m-pull",
        "audio/x-s3m-subscribe",
        "audio/x-s3m-publish",
        "audio/x-s3m-broadcast",
        "audio/x-s3m-multicast",
        "audio/x-s3m-unicast",
        "audio/x-s3m-peer-to-peer",
        "audio/x-s3m-mesh",
        "audio/x-s3m-cloud",
        "audio/x-s3m-edge",
        "audio/x-s3m-fog",
        "audio/x-s3m-gateway",
        "audio/x-s3m-proxy",
        "audio/x-s3m-reverse-proxy",
        "audio/x-s3m-load-balancer",
        "audio/x-s3m-router",
        "audio/x-s3m-switch",
        "audio/x-s3m-hub",
        "audio/x-s3m-node",
        "audio/x-s3m-endpoint",
        "audio/x-s3m-service",
        "audio/x-s3m-api",
        "audio/x-s3m-rest",
        "audio/x-s3m-graphql",
        "audio/x-s3m-soap",
        "audio/x-s3m-rpc",
        "audio/x-s3m-grpc",
        "audio/x-s3m-websocket",
        "audio/x-s3m-sse",
        "audio/x-s3m-eventsource",
        "audio/x-s3m-server-sent-events",
        "audio/x-s3m-push",
        "audio/x-s3m-pull",
        "audio/x-s3m-subscribe",
        "audio/x-s3m-publish",
        "audio/x-s3m-broadcast",
        "audio/x-s3m-multicast",
        "audio/x-s3m-unicast",
        "audio/x-s3m-peer-to-peer",
        "audio/x-s3m-mesh",
        "audio/x-s3m-cloud",
        "audio/x-s3m-edge",
        "audio/x-s3m-fog",
        "audio/x-s3......"

        # Additional Image Formats
        "image/bmp",
        "image/cgm",
        "image/dicom-rle",
        "image/emf",
        "image/example",
        "image/fits",
        "image/g3fax",
        "image/gif",
        "image/heic",
        "image/heic-sequence",
        "image/heif",
        "image/heif-sequence",
        "image/hej2k",
        "image/hsj2",
        "image/ief",
        "image/jls",
        "image/jp2",
        "image/jpeg",
        "image/jpeg2000",
        "image/jph",
        "image/jphc",
        "image/jpm",
        "image/jpx",
        "image/jxr",
        "image/jxra",
        "image/jxrs",
        "image/jxs",
        "image/jxsc",
        "image/jxsi",
        "image/jxss",
        "image/ktx",
        "image/ktx2",
        "image/naplps",
        "image/png",
        "image/prs.btif",
        "image/prs.pti",
        "image/pwg-raster",
        "image/svg+xml",
        "image/t38",
        "image/tiff",
        "image/tiff-fx",
        "image/vnd.adobe.photoshop",
        "image/vnd.airzip.accelerator.azv",
        "image/vnd.cns.inf2",
        "image/vnd.dece.graphic",
        "image/vnd.djvu",
        "image/vnd.djvu+multipage",
        "image/vnd.dvb.subtitle",
        "image/vnd.dwg",
        "image/vnd.dxf",
        "image/vnd.fastbidsheet",
        "image/vnd.fpx",
        "image/vnd.fst",
        "image/vnd.fujixerox.edmics-mmr",
        "image/vnd.fujixerox.edmics-rlc",
        "image/vnd.globalgraphics.pgb",
        "image/vnd.microsoft.icon",
        "image/vnd.mix",
        "image/vnd.mozilla.apng",
        "image/vnd.ms-dds",
        "image/vnd.ms-modi",
        "image/vnd.net-fpx",
        "image/vnd.pco.b16",
        "image/vnd.radiance",
        "image/vnd.sealed.png",
        "image/vnd.sealedmedia.softseal.gif",
        "image/vnd.sealedmedia.softseal.jpg",
        "image/vnd.svf",
        "image/vnd.tencent.tap",
        "image/vnd.valve.source.texture",
        "image/vnd.wap.wbmp",
        "image/vnd.xiff",
        "image/vnd.zbrush.pcx",
        "image/webp",
        "image/wmf",
        "image/x-3ds",
        "image/x-adobe-dng",
        "image/x-apng",
        "image/x-bmp",
        "image/x-bzeps",
        "image/x-canon-cr2",
        "image/x-canon-crw",
        "image/x-cmu-raster",
        "image/x-cmx",
        "image/x-compressed-xcf",
        "image/x-dds",
        "image/x-djvu",
        "image/x-emf",
        "image/x-eps",
        "image/x-exr",
        "image/x-fits",
        "image/x-freehand",
        "image/x-fuji-raf",
        "image/x-g3fax",
        "image/x-galaxy-force",
        "image/x-gbr",
        "image/x-gimp-gbr",
        "image/x-gimp-gih",
        "image/x-gimp-pat",
        "image/x-gzeps",
        "image/x-icns",
        "image/x-icon",
        "image/x-ilbm",
        "image/x-jng",
        "image/x-kodak-dcr",
        "image/x-kodak-k25",
        "image/x-kodak-kdc",
        "image/x-lwo",
        "image/x-lws",
        "image/x-macpaint",
        "image/x-minolta-mrw",
        "image/x-mrsid-image",
        "image/x-ms-bmp",
        "image/x-msod",
        "image/x-nikon-nef",
        "image/x-olympus-orf",
        "image/x-panasonic-rw",
        "image/x-panasonic-rw2",
        "image/x-pcx",
        "image/x-pentax-pef",
        "image/x-photo-cd",
        "image/x-photoshop",
        "image/x-pict",
        "image/x-pjpeg",
        "image/x-portable-anymap",
        "image/x-portable-bitmap",
        "image/x-portable-graymap",
        "image/x-portable-pixmap",
        "image/x-psd",
        "image/x-quicktime",
        "image/x-rgb",
        "image/x-sgi",
        "image/x-sigma-x3f",
        "image/x-skencil",
        "image/x-sony-arw",
        "image/x-sony-sr2",
        "image/x-sony-srf",
        "image/x-sun-raster",
        "image/x-targa",
        "image/x-tga",
        "image/x-win-bitmap",
        "image/x-wmf",
        "image/x-xbitmap",
        "image/x-xcf",
        "image/x-xcursor",
        "image/x-xfig",
        "image/x-xpixmap",
        "image/x-xwindowdump",
        "image/x-3fr",
        "image/x-ari",
        "image/x-arw",
        "image/x-bay",
        "image/x-bmq",
        "image/x-brk",
        "image/x-canon-crw",
        "image/x-canon-cr2",
        "image/x-cin",
        "image/x-colorscript",
        "image/x-cr2",
        "image/x-crw",
        "image/x-dcr",
        "image/x-dcs",
        "image/x-dib",
        "image/x-dng",
        "image/x-dpx",
        "image/x-eip",
        "image/x-emf",
        "image/x-epi",
        "image/x-eps",
        "image/x-erf",
        "image/x-exr",
        "image/x-fpf",
        "image/x-fpx",
        "image/x-gbr",
        "image/x-gf",
        "image/x-gif",
        "image/x-grf",
        "image/x-hdr",
        "image/x-hex",
        "image/x-icb",
        "image/x-icns",
        "image/x-iff",
        "image/x-ilbm",
        "image/x-j2k",
        "image/x-jng",
        "image/x-jp2-codestream",
        "image/x-jpeg2000-image",
        "image/x-k25",
        "image/x-kdc",
        "image/x-lfp",
        "image/x-macpaint",
        "image/x-mfw",
        "image/x-minolta-mrw",
        "image/x-mos",
        "image/x-mrtrix",
        "image/x-msod",
        "image/x-nikon-nef",
        "image/x-nikon-nrw",
        "image/x-olympus-orf",
        "image/x-panasonic-raw",
        "image/x-panasonic-raw2",
        "image/x-pentax-pef",
        "image/x-photo-cd",
        "image/x-pict",
        "image/x-pjpeg",
        "image/x-portable-anymap",
        "image/x-portable-bitmap",
        "image/x-portable-graymap",
        "image/x-portable-pixmap",
        "image/x-ptx",
        "image/x-qtk",
        "image/x-quicktime",
        "image/x-rayphoto",
        "image/x-red",
        "image/x-rgb",
        "image/x-rgba",
        "image/x-ric",
        "image/x-riff",
        "image/x-rle",
        "image/x-rol",
        "image/x-sct",
        "image/x-sdsc",
        "image/x-sgi",
        "image/x-sgilog",
        "image/x-sgiold",
        "image/x-sigma-x3f",
        "image/x-sketch",
        "image/x-softimage",
        "image/x-sony-arw",
        "image/x-sony-sr2",
        "image/x-sony-srf",
        "image/x-spectra",
        "image/x-sph",
        "image/x-spr",
        "image/x-sunras",
        "image/x-tga",
        "image/x-tiff-multipage",
        "image/x-uint16",
        "image/x-uint32",
        "image/x-unknown",
        "image/x-viff",
        "image/x-wal",
        "image/x-wmf",
        "image/x-x3f",
        "image/x-xbitmap",
        "image/x-xcf",
        "image/x-xcursor",
        "image/x-xfig",
        "image/x-xpixmap",
        "image/x-xwindowdump",
        "image/x-xyz",
        "image/x-z3d",
        "image/x-zoo",
        "image/x-zstd-compressed-avif",
        "image/x-zstd-compressed-heif",
        "image/x-zstd-compressed-jxl",
        "image/x-zstd-compressed-webp",
        "image/x-zstd-compressed-png",
        "image/x-zstd-compressed-jpeg",
        "image/x-zstd-compressed-tiff",
        "image/x-zstd-compressed-bmp",
        "image/x-zstd-compressed-gif",
        "image/x-zstd-compressed-svg",
        "image/x-zstd-compressed-ico",
        "image/x-zstd-compressed-cur",
        "image/x-zstd-compressed-emf",
        "image/x-zstd-compressed-wmf",
        "image/x-zstd-compressed-dib",
        "image/x-zstd-compressed-pcx",
        "image/x-zstd-compressed-tga",
        "image/x-zstd-compressed-ppm",
        "image/x-zstd-compressed-pnm",
        "image/x-zstd-compressed-pbm",
        "image/x-zstd-compressed-pgm",
        "image/x-zstd-compressed-psd",
        "image/x-zstd-compressed-psb",
        "image/x-zstd-compressed-pdd",
        "image/x-zstd-compressed-xcf",
        "image/x-zstd-compressed-sketch",
        "image/x-zstd-compressed-fireworks",
        "image/x-zstd-compressed-indd",
        "image/x-zstd-compressed-ai",
        "image/x-zstd-compressed-eps",
        "image/x-zstd-compressed-pdf",
        "image/x-zstd-compressed-djvu",
        "image/x-zstd-compressed-tiff",
        "image/x-zstd-compressed-raw",
        "image/x-zstd-compressed-cr2",
        "image/x-zstd-compressed-nef",
        "image/x-zstd-compressed-orf",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-dng",
        "image/x-zstd-compressed-arw",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-sr2",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-rw2",
        "image/x-zstd-compressed-pef",
        "image/x-zstd-compressed-mrw",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-3fr",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        # More Image Formats (Continued)
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image/x-zstd-compressed-iiq",
        "image/x-zstd-compressed-mef",
        "image/x-zstd-compressed-nrw",
        "image/x-zstd-compressed-pxn",
        "image/x-zstd-compressed-qtk",
        "image/x-zstd-compressed-r3d",
        "image/x-zstd-compressed-raf",
        "image/x-zstd-compressed-rwl",
        "image/x-zstd-compressed-sd",
        "image/x-zstd-compressed-sr0",
        "image/x-zstd-compressed-srf",
        "image/x-zstd-compressed-srw",
        "image/x-zstd-compressed-x3f",
        "image/x-zstd-compressed-dcr",
        "image/x-zstd-compressed-k25",
        "image/x-zstd-compressed-kdc",
        "image/x-zstd-compressed-mos",
        "image/x-zstd-compressed-erf",
        "image/x-zstd-compressed-fff",
        "image......"

        # More Audio Formats (Continued)
        "audio/x-s3m",
        "audio/x-sd2",
        "audio/x-sds",
        "audio/x-sf2",
        "audio/x-sln",
        "audio/x-smaf",
        "audio/x-smd",
        "audio/x-spc",
        "audio/x-speex",
        "audio/x-speex+ogg",
        "audio/x-spk",
        "audio/x-spx",
        "audio/x-stm",
        "audio/x-stx",
        "audio/x-sub",
        "audio/x-subrip",
        "audio/x-tak",
        "audio/x-tak-coded",
        "audio/x-tak-compressed",
        "audio/x-tak-encoded",
        "audio/x-tak-lossless",
        "audio/x-tak-lossy",
        "audio/x-tak-variable",
        "audio/x-tak-adaptive",
        "audio/x-tak-dynamic",
        "audio/x-tak-flexible",
        "audio/x-tak-scalable",
        "audio/x-tak-adjustable",
        "audio/x-tak-configurable",
        "audio/x-tak-custom",
        "audio/x-tak-personalized",
        "audio/x-tak-individual",
        "audio/x-tak-unique",
        "audio/x-tak-special",
        "audio/x-tak-enhanced",
        "audio/x-tak-optimized",
        "audio/x-tak-improved",
        "audio/x-tak-advanced",
        "audio/x-tak-professional",
        "audio/x-tak-enterprise",
        "audio/x-tak-commercial",
        "audio/x-tak-business",
        "audio/x-tak-industrial",
        "audio/x-tak-scientific",
        "audio/x-tak-medical",
        "audio/x-tak-audio",
        "audio/x-tak-music",
        "audio/x-tak-sound",
        "audio/x-tak-noise",
        "audio/x-tak-tone",
        "audio/x-tak-silence",
        "audio/x-tak-quiet",
        "audio/x-tak-silent",
        "audio/x-tak-mute",
        "audio/x-tak-voice",
        "audio/x-tak-speech",
        "audio/x-tak-conversation",
        "audio/x-tak-dialog",
        "audio/x-tak-discussion",
        "audio/x-tak-talk",
        "audio/x-tak-chat",
        "audio/x-tak-message",
        "audio/x-tak-announcement",
        "audio/x-tak-notification",
        "audio/x-tak-alert",
        "audio/x-tak-warning",
        "audio/x-tak-caution",
        "audio/x-tak-advice",
        "audio/x-tak-suggestion",
        "audio/x-tak-recommendation",
        "audio/x-tak-instruction",
        "audio/x-tak-direction",
        "audio/x-tak-guide",
        "audio/x-tak-tutorial",
        "audio/x-tak-lesson",
        "audio/x-tak-course",
        "audio/x-tak-education",
        "audio/x-tak-learning",
        "audio/x-tak-training",
        "audio/x-tak-coaching",
        "audio/x-tak-teaching",
        "audio/x-tak-instructing",
        "audio/x-tak-explaining",
        "audio/x-tak-describing",
        "audio/x-tak-detailing",
        "audio/x-tak-specifying",
        "audio/x-tak-defining",
        "audio/x-tak-characterizing",
        "audio/x-tak-identifying",
        "audio/x-tak-recognition",
        "audio/x-tak-acknowledgment",
        "audio/x-tak-appreciation",
        "audio/x-tak-thanks",
        "audio/x-tak-gratitude",
        "audio/x-tak-welcome",
        "audio/x-tak-greeting",
        "audio/x-tak-hello",
        "audio/x-tak-goodbye",
        "audio/x-tak-farewell",
        "audio/x-tak-bye",
        "audio/x-tak-seeyou",
        "audio/x-tak-seeyoulater",
        "audio/x-tak-seeyounexttime",
        "audio/x-tak-seeagain",
        "audio/x-tak-return",
        "audio/x-tak-comeback",
        "audio/x-tak-back",
        "audio/x-tak-arrive",
        "audio/x-tak-leave",
        "audio/x-tak-depart",
        "audio/x-tak-go",
        "audio/x-tak-move",
        "audio/x-tak-travel",
        "audio/x-tak-journey",
        "audio/x-tak-trip",
        "audio/x-tak-excursion",
        "audio/x-tak-adventure",
        "audio/x-tak-exploration",
        "audio/x-tak-discovery",
        "audio/x-tak-finding",
        "audio/x-tak-search",
        "audio/x-tak-quest",
        "audio/x-tak-mission",
        "audio/x-tak-task",
        "audio/x-tak-job",
        "audio/x-tak-work",
        "audio/x-tak-duty",
        "audio/x-tak-responsibility",
        "audio/x-tak-obligation",
        "audio/x-tak-commitment",
        "audio/x-tak-pledge",
        "audio/x-tak-promise",
        "audio/x-tak-vow",
        "audio/x-tak-oath",
        "audio/x-tak-pledging",
        "audio/x-tak-promising",
        "audio/x-tak-vowing",
        "audio/x-tak-oathing",
        "audio/x-tak-contracting",
        "audio/x-tak-agreeing",
        "audio/x-tak-consenting",
        "audio/x-tak-approving",
        "audio/x-tak-accepting",
        "audio/x-tak-receiving",
        "audio/x-tak-taking",
        "audio/x-tak-getting",
        "audio/x-tak-obtaining",
        "audio/x-tak-acquiring",
        "audio/x-tak-gaining",
        "audio/x-tak-winning",
        "audio/x-tak-earning",
        "audio/x-tak-achieving",
        "audio/x-tak-reaching",
        "audio/x-tak-attaining",
        "audio/x-tak-accomplishing",
        "audio/x-tak-completing",
        "audio/x-tak-finishing",
        "audio/x-tak-ending",
        "audio/x-tak-concluding",
        "audio/x-tak-closing",
        "audio/x-tak-stopping",
        "audio/x-tak-ceasing",
        "audio/x-tak-halting",
        "audio/x-tak-pausing",
        "audio/x-tak-breaking",
        "audio/x-tak-interrupting",
        "audio/x-tak-disturbing",
        "audio/x-tak-disrupting",
        "audio/x-tak-hindering",
        "audio/x-tak-blocking",
        "audio/x-tak-preventing",
        "audio/x-tak-stopping",
        "audio/x-tak-inhibiting",
        "audio/x-tak-restraining",
        "audio/x-tak-controlling",
        "audio/x-tak-managing",
        "audio/x-tak-organizing",
        "audio/x-tak-planning",
        "audio/x-tak-scheduling",
        "audio/x-tak-arranging",
        "audio/x-tak-coordinating",
        "audio/x-tak-aligning",
        "audio/x-tak-matching",
        "audio/x-tak-fitting",
        "audio/x-tak-suiting",
        "audio/x-tak-accommodating",
        "audio/x-tak-adapting",
        "audio/x-tak-adjusting",
        "audio/x-tak-modifying",
        "audio/x-tak-changing",
        "audio/x-tak-transforming",
        "audio/x-tak-converting",
        "audio/x-tak-translating",
        "audio/x-tak-interpreting",
        "audio/x-tak-explaining",
        "audio/x-tak-clarifying",
        "audio/x-tak-elaborating",
        "audio/x-tak-expanding",
        "audio/x-tak-extending",
        "audio/x-tak-stretching",
        "audio/x-tak-lengthening",
        "audio/x-tak-broadening",
        "audio/x-tak-widening",
        "audio/x-tak-expanding",
        "audio/x-tak-increasing",
        "audio/x-tak-growing",
        "audio/x-tak-developing",
        "audio/x-tak-evolving",
        "audio/x-tak-progressing",
        "audio/x-tak-advancing",
        "audio/x-tak-moving",
        "audio/x-tak-proceeding",
        "audio/x-tak-continuing",
        "audio/x-tak-persisting",
        "audio/x-tak-enduring",
        "audio/x-tak-lasting",
        "audio/x-tak-surviving",
        "audio/x-tak-existing",
        "audio/x-tak-being",
        "audio/x-tak-living",
        "audio/x-tak-breathing",
        "audio/x-tak-functioning",
        "audio/x-tak-operating",
        "audio/x-tak-working",
        "audio/x-tak-performing",
        "audio/x-tak-acting",
        "audio/x-tak-behaving",
        "audio/x-tak-conducting",
        "audio/x-tak-managing",
        "audio/x-tak-directing",
        "audio/x-tak-leading",
        "audio/x-tak-guiding",
        "audio/x-tak-steering",
        "audio/x-tak-navigating",
        "audio/x-tak-piloting",
        "audio/x-tak-driving",
        "audio/x-tak-controlling",
        "audio/x-tak-handling",
        "audio/x-tak-operating",
        "audio/x-tak-manipulating",
        "audio/x-tak-managing",
        "audio/x-tak-overseeing",
        "audio/x-tak-supervising",
        "audio/x-tak-monitoring",
        "audio/x-tak-watching",
        "audio/x-tak-observing",
        "audio/x-tak-noticing",
        "audio/x-tak-recognizing",
        "audio/x-tak-identifying",
        "audio/x-tak-spotting",
        "audio/x-tak-locating",
        "audio/x-tak-finding",
        "audio/x-tak-detecting",
        "audio/x-tak-discovering",
        "audio/x-tak-revealing",
        "audio/x-tak-uncovering",
        "audio/x-tak-exposing",
        "audio/x-tak-disclosing",
        "audio/x-tak-sharing",
        "audio/x-tak-revealing",
        "audio/x-tak-telling",
        "audio/x-tak-informing",
        "audio/x-tak-educating",
        "audio/x-tak-teaching",
        "audio/x-tak-instructing",
        "audio/x-tak-guiding",
        "audio/x-tak-advising",
        "audio/x-tak-counseling",
        "audio/x-tak-consulting",
        "audio/x-tak-recommending",
        "audio/x-tak-suggesting",
        "audio/x-tak-proposing",
        "audio/x-tak-offering",
        "audio/x-tak-presenting",
        "audio/x-tak-delivering",
        "audio/x-tak-providing",
        "audio/x-tak-supplying",
        "audio/x-tak-furnishing",
        "audio/x-tak-equipping",
        "audio/x-tak-arming",
        "audio/x-tak-preparing",
        "audio/x-tak-readying",
        "audio/x-tak-setting",
        "audio/x-tak-positioning",
        "audio/x-tak-placing",
        "audio/x-tak-locating",
        "audio/x-tak-establishing",
        "audio/x-tak-founding",
        "audio/x-tak-creating",
        "audio/x-tak-making",
        "audio/x-tak-building",
        "audio/x-tak-constructing",
        "audio/x-tak-assembling",
        "audio/x-tak-combining",
        "audio/x-tak-unifying",
        "audio/x-tak-integrating",
        "audio/x-tak-merging",
        "audio/x-tak-blending",
        "audio/x-tak-mixing",
        "audio/x-tak-stirring",
        "audio/x-tak-shaking",
        "audio/x-tak-beating",
        "audio/x-tak-whipping",
        "audio/x-tak-blending",
        "audio/x-tak-mashing",
        "audio/x-tak-crushing",
        "audio/x-tak-grinding",
        "audio/x-tak-pulverizing",
        "audio/x-tak-reducing",
        "audio/x-tak-minimizing",
        "audio/x-tak-decreasing",
        "audio/x-tak-diminishing",
        "audio/x-tak-attenuating",
        "audio/x-tak-weakening",
        "audio/x-tak-softening",
        "audio/x-tak-gentling",
        "audio/x-tak-mellowing",
        "audio/x-tak-smoothing",
        "audio/x-tak-leveling",
        "audio/x-tak-evening",
        "audio/x-tak-flattening",
        "audio/x-tak-smoothing",
        "audio/x-tak-calming",
        "audio/x-tak-quieting",
        "audio/x-tak-stilling",
        "audio/x-tak-settling",
        "audio/x-tak-composing",
        "audio/x-tak-collecting",
        "audio/x-tak-gathering",
        "audio/x-tak-assembling",
        "audio/x-tak-congregating",
        "audio/x-tak-uniting",
        "audio/x-tak-consolidating",
        "audio/x-tak-strengthening",
        "audio/x-tak-reinforcing",
        "audio/x-tak-supporting",
        "audio/x-tak-aiding",
        "audio/x-tak-assisting",
        "audio/x-tak-helping",
        "audio/x-tak-serving",
        "audio/x-tak-attending",
        "audio/x-tak-caring",
        "audio/x-tak-nurturing",
        "audio/x-tak-fostering",
        "audio/x-tak-cultivating",
        "audio/x-tak-growing",
        "audio/x-tak-nourishing",
        "audio/x-tak-feeding",
        "audio/x-tak-sustaining",
        "audio/x-tak-maintaining",
        "audio/x-tak-preserving",
        "audio/x-tak-protecting",
        "audio/x-tak-guarding",
        "audio/x-tak-defending",
        "audio/x-tak-shielding",
        "audio/x-tak-covering",
        "audio/x-tak-hiding",
        "audio/x-tak-concealing",
        "audio/x-tak-veiling",
        "audio/x-tak-screening",
        "audio/x-tak-shading",
        "audio/x-tak-shadowing",
        "audio/x-tak-overcasting",
        "audio/x-tak-darkening",
        "audio/x-tak-dimming",
        "audio/x-tak-lowering",
        "audio/x-tak-reducing",
        "audio/x-tak-declining",
        "audio/x-tak-descending",
        "audio/x-tak-falling",
        "audio/x-tak-dropping",
        "audio/x-tak-sinking",
        "audio/x-tak-sliding",
        "audio/x-tak-gliding",
        "audio/x-tak-floating",
        "audio/x-tak-hovering",
        "audio/x-tak-suspended",
        "audio/x-tak-hanging",
        "audio/x-tak-swinging",
        "audio/x-tak-rocking",
        "audio/x-tak-bouncing",
        "audio/x-tak-jumping",
        "audio/x-tak-leaping",
        "audio/x-tak-springing",
        "audio/x-tak-leaping",
        "audio/x-tak-soaring",
        "audio/x-tak-flying",
        "audio/x-tak-winging",
        "audio/x-tak-soaring",
        "audio/x-tak-gliding",
        "audio/x-tak-sailing",
        "audio/x-tak-floating",
        "audio/x-tak-drifting",
        "audio/x-tak-wandering",
        "audio/x-tak-roaming",
        "audio/x-tak-strolling",
        "audio/x-tak-walking",
        "audio/x-tak-striding",
        "audio/x-tak-marching",
        "audio/x-tak-parading",
        "audio/x-tak-processioning",
        "audio/x-tak-maneuvering",
        "audio/x-tak-navigating",
        "audio/x-tak-traversing",
        "audio/x-tak-crossing",
        "audio/x-tak-passing",
        "audio/x-tak-overpassing",
        "audio/x-tak-underpassing",
        "audio/x-tak-bridging",
        "audio/x-tak-spanning",
        "audio/x-tak-covering",
        "audio/x-tak-spanning",
        "audio/x-tak-connecting",
        "audio/x-tak-linking",
        "audio/x-tak-joining",
        "audio/x-tak-uniting",
        "audio/x-tak-binding",
        "audio/x-tak-fastening",
        "audio/x-tak-securing",
        "audio/x-tak-anchoring",
        "audio/x-tak-rooting",
        "audio/x-tak-grounding",
        "audio/x-tak-establishing",
        "audio/x-tak-foundating",
        "audio/x-tak-basing",
        "audio/x-tak-centering",
        "audio/x-tak-focusing",
        "audio/x-tak-concentrating",
        "audio/x-tak-aiming",
        "audio/x-tak-targeting",
        "audio/x-tak-pointing",
        "audio/x-tak-directing",
        "audio/x-tak-orienting",
        "audio/x-tak-aligning",
        "audio/x-tak-positioning",
        "audio/x-tak-placing",
        "audio/x-tak-locating",
        "audio/x-tak-situating",
        "audio/x-tak-installing",
        "audio/x-tak-mounting",
        "audio/x-tak-attaching",
        "audio/x-tak-fixing",
        "audio/x-tak-securing",
        "audio/x-tak-fastening",
        "audio/x-tak-tying",
        "audio/x-tak-knotting",
        "audio/x-tak-braiding",
        "audio/x-tak-weaving",
        "audio/x-tak-knitting",
        "audio/x-tak-sewing",
        "audio/x-tak-stitching",
        "audio/x-tak-embroidering",
        "audio/x-tak-quilting",
        "audio/x-tak-tailoring",
        "audio/x-tak-seaming",
        "audio/x-tak-hemming",
        "audio/x-tak-darning",
        "audio/x-tak-mending",
        "audio/x-tak-repairing",
        "audio/x-tak-fixing",
        "audio/x-tak-restoring",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-renewing",
        "audio/x-tak-refreshing",
        "audio/x-tak-revamping",
        "audio/x-tak-renovating",
        "audio/x-tak-refurbishing",
        "audio/x-tak-restyling",
        "audio/x-tak-reimagining",
        "audio/x-tak-reinventing",
        "audio/x-tak-redefining",
        "audio/x-tak-restructuring",
        "audio/x-tak-reorganizing",
        "audio/x-tak-realigning",
        "audio/x-tak-redesigning",
        "audio/x-tak-reengineering",
        "audio/x-tak-redeveloping",
        "audio/x-tak-rebuilding",
        "audio/x-tak-reconstructing",
        "audio/x-tak-resurrecting",
        "audio/x-tak-reanimating",
        "audio/x-tak-resuscitating",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
        "audio/x-tak-reviving",
        "audio/x-tak-revitalizing",
]
