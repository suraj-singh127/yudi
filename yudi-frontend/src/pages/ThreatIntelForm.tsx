import { useState } from "react";
import axios from "axios";
import { Box, Button, Input, Textarea, Stack, Heading, Text } from "@chakra-ui/react";

export default function IOCInputPage() {
  const [iocData, setIocData] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setFile(event.target.files[0]);
    }
  };

  const handleSubmit = async () => {
    setLoading(true);
    const formData = new FormData();
    
    if (file) {
      formData.append("file", file);
    } else if (iocData.trim()) {
      formData.append("manual_input", iocData);
    }

    try {
      await axios.post("/api/ioc/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      alert("Upload successful");
    } catch (error) {
      alert("Upload failed");
    }
    setLoading(false);
  };

  return (
    <Box display="flex" alignItems="center" justifyContent="center" minH="100vh" bg="gray.900" color="white" p={4}>
      <Box bg="gray.800" p={6} borderRadius="lg" boxShadow="lg" maxW="md" w="full">
        <Stack spacing={4}>
          <Heading size="md" textAlign="center">Upload IOCs</Heading>
          <Text fontSize="sm" color="gray.400" textAlign="center">Supports JSON, CSV, STIX, TXT</Text>
          <Input type="file" accept=".json,.csv,.txt,.stix" onChange={handleFileChange} bg="gray.700" borderColor="gray.600" />
          <Text fontSize="sm" color="gray.400" textAlign="center">Or manually enter IOCs:</Text>
          <Textarea rows={4} value={iocData} onChange={(e) => setIocData(e.target.value)} placeholder="Paste IOCs..." bg="gray.700" borderColor="gray.600" />
          <Button colorScheme="blue" onClick={handleSubmit} isLoading={loading} w="full">
            Submit
          </Button>
        </Stack>
      </Box>
    </Box>
  );
}
