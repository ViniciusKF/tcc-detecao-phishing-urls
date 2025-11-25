# Sistema experimental de detecção de phishing em URLs

Este repositório reúne o código-fonte desenvolvido para um Trabalho de Conclusão
de Curso (TCC) em Ciência da Computação. O objetivo é implementar e avaliar um
sistema experimental de detecção de phishing baseado exclusivamente em URLs,
com foco em baixa latência e interpretabilidade das decisões.

O projeto é composto por três partes:

- **Backend (API em FastAPI)**  
  Serviço responsável por receber URLs, extrair características da string
  e aplicar um modelo de classificação treinado (Regressão Logística).

- **Interface Web (Next.js)**  
  Aplicação web simples para envio de URLs, visualização do risco estimado
  e das explicações associadas à decisão do modelo.

- **Extensão de Navegador (Manifest V3)**  
  Extensão experimental que lê a URL ativa, consulta a API e exibe alertas
  ao usuário em caso de suspeita de phishing.
