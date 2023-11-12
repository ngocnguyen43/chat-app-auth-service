import axios from 'axios';

export const getService = async (name: string) => {
  try {
    const res = await axios.get(`http://127.0.0.1:8500/v1/agent/health/service/name/${name}`).then(data => data.data);
    console.log(res)
    return (res[0] as [])['Service']['Service'];
  } catch (error) {
    console.log(error);
    return '';
  }
};
