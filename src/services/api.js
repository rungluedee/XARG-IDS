import axios from "axios";

const API_BASE_URL = "http://localhost:8000"; // เปลี่ยนตาม Port ที่อัปสั่ง uvicorn run

export const analyzePcapFile = async (file) => {
  const formData = new FormData();
  formData.append("file", file);

  const response = await axios.post(`${API_BASE_URL}/api/analyze-pcap`, formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });

  return response.data;
};