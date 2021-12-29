using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xceed.Words.NET;

// Modified source code from: https://docs.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.altchunk?view=openxml-2.8.1

namespace SharpAltChunk
{
    class Program
    {
        public static void createDoc(string docName)
        {
            var doc = DocX.Create(docName);
            doc.Save();
        }

        public static void altChunkEmbed(string fileName1, string fileName2, string type)
        {
            string testFile = @"c:\dh\final-test.docx";
            createDoc(testFile);
            File.Delete(fileName1);
            File.Copy(testFile, fileName1);

            using (WordprocessingDocument myDoc =
    WordprocessingDocument.Open(fileName1, true))
            {
                Random rnd = new Random();
                string altChunkId = "AltChunkId" + rnd.Next(1, 1000).ToString();
                MainDocumentPart mainPart = myDoc.MainDocumentPart;

                AlternativeFormatImportPart chunk = null; 
                if (type.ToLower() == "docx")
                {
                    chunk = mainPart.AddAlternativeFormatImportPart(AlternativeFormatImportPartType.WordprocessingML, altChunkId);
                }
                else if(type.ToLower() == "rtf")
                {
                    chunk = mainPart.AddAlternativeFormatImportPart(AlternativeFormatImportPartType.Rtf, altChunkId);
                }
                else
                {
                    Console.WriteLine("[-] Type needs to be either docx or rtf. Exiting.");
                    Environment.Exit(1);
                }


                using (FileStream fileStream = File.Open(fileName2, FileMode.Open))
                    chunk.FeedData(fileStream);
                AltChunk altChunk = new AltChunk();
                altChunk.Id = altChunkId;
                mainPart.Document
                    .Body
                    .InsertAfter(altChunk, mainPart.Document.Body
                    .Elements<Paragraph>().Last());


                mainPart.Document.Save();
            }
        }
        static void Main(string[] args)
        {
            // Embed RTF into afchunk2.docx
            string sourceFile = @"C:\dh\afchunk.rtf";
            string destinationFile = @"C:\dh\afchunk2.docx";
            createDoc(destinationFile);
            altChunkEmbed(destinationFile, sourceFile, "rtf");
            Console.WriteLine("[+] Embedding {0} to {1} ...", sourceFile, destinationFile);
            
            // Embed afchunk2.docx into final.docx
            sourceFile = @"C:\dh\afchunk2.docx";
            destinationFile = @"c:\dh\final.docx";
            createDoc(destinationFile);
            altChunkEmbed(destinationFile, sourceFile, "docx");
            Console.WriteLine("[+] Embedding {0} to {1} ...", sourceFile, destinationFile);

            Console.WriteLine("\n[+] Embedding done. Check {0}",destinationFile);
         }
    }
}
